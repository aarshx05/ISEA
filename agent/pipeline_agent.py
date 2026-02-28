"""
Pipeline Agent — Deep Forensic Reasoning Engine

Unlike the ForensicAgent which handles open-ended chat, the PipelineAgent
is embedded directly into the ISEA scanning pipeline. It makes synchronous,
structured calls to the Groq LLM to perform deterministic forensic reasoning
mid-scan: correlating signals, testing alternative hypotheses, optionally
asking the investigator targeted clarifying questions, and producing a fully
traceable verdict with an evidence chain.

Key design principles:
  - The agent decides WHETHER to ask questions (not forced to ask every time)
  - Maximum 2 targeted questions before a verdict must be rendered
  - Each question includes a reasoning field (why this specific answer matters)
  - Each verdict includes an evidence_chain (traceable, signal-by-signal reasoning)
  - <think> blocks stream live to the Activity Log as agent_thought events
"""

import json
import logging
import re
import sys
import time
import traceback
from typing import Any

from groq import Groq
from config import config

logger = logging.getLogger(__name__)

# Maximum questions the agent may ask before being forced to render a verdict
_MAX_QUESTIONS = 2
# Total turn ceiling (question + answer pairs + verdict)
_MAX_TURNS = 8
# Tokens — generous budget for <think> reasoning + full JSON verdict
_MAX_TOKENS = 2500
# Retry attempts on transient Groq errors (rate limit, 503, network hiccup)
_MAX_RETRIES = 3


# ---------------------------------------------------------------------------
# Deep forensic analyst system prompt
# ---------------------------------------------------------------------------

_BASE_INSTRUCTION = """You are a senior digital forensics analyst with 15+ years of experience \
investigating evidence tampering, insider threats, and data destruction cases. \
You are embedded in ISEA — an AI-powered disk forensics platform.

Your task: analyze raw disk wipe evidence and determine whether the activity represents \
intentional evidence destruction, and if so, by whom and for what purpose.

## Analytical Methodology (follow this precisely in every response)

STEP 1 — SIGNAL CORRELATION:
In your <think> block, analyze each signal individually, then look for reinforcing \
patterns AND contradictions. Ask: What does each signal indicate in isolation? \
What does the combination suggest? Do any signals contradict each other?

STEP 2 — ALTERNATIVE HYPOTHESES:
Before concluding malicious intent, explicitly test the benign hypothesis. \
Could this be authorized IT decommissioning? Accidental deletion? A backup tool? A factory reset? \
Identify which specific signals RULE OUT each benign explanation.

STEP 3 — DECIDE: QUESTION OR CONCLUDE?
Ask a clarifying question ONLY when BOTH conditions are true:
  (a) A specific piece of context you don't have would change your final score by 20+ points.
  (b) The question is specific, answerable in one sentence, and forensically actionable.
If the evidence is clear-cut (e.g., selective wipe of sensitive directories immediately \
after file deletions), render a verdict directly. Do NOT ask questions for the sake of it.

STEP 4 — VERDICT:
Produce a calibrated score with a full evidence chain. Every entry in evidence_chain \
must cite a specific signal and explain what it implies for intent.

## Signal Interpretation Guide

wipe_scope=full_disk:   Ambiguous — authorized IT reimaging OR scorched-earth. Needs context.
wipe_scope=partition:   Moderate suspicion — could be OS reinstall or targeted partition wipe.
wipe_scope=selective:   HIGH suspicion. Deliberate file-level targeting = destruction of specific evidence.
is_localized=True:      Targeted operation. Combined with sensitive dirs → very high suspicion.
temporal_correlation:   Wipes follow deletion events — classic cover-up sequence. Strong indicator.
sensitive_targeted:     Finance, legal, HR, crypto directories = perpetrator knew what to destroy.
hidden_volume_count>0:  CRITICAL — plausible deniability architecture. Almost never accidental.
intensity > 85%:        Thorough, planned wipe operation. Deliberate.
intensity 30-85%:       Moderate. Could be interrupted wipe or partial tool run.
intensity < 30%:        Weak signal — possible tool failure, false positive, or trivial operation.
wipe_fraction < 5%:     Very small disk footprint — could be routine maintenance.
wipe_fraction > 50%:    Large footprint — significant data destruction.

## Score Calibration

90-100: Near-certain evidence destruction. Chain-of-custody documentation required immediately.
70-89:  Highly probable intentional destruction. Strong indicators, minimal benign explanation.
50-69:  Probable. Multiple indicators present but some ambiguity remains.
30-49:  Possible. Signals present but benign explanations not fully ruled out.
10-29:  Minimal. Weak signals, likely routine activity.
0-9:    Negligible. No meaningful indicators of intentional destruction.

## Reasoning Quality Standard

Your <think> block MUST:
- Name each signal explicitly and state its specific forensic implication
- Identify which signals are corroborating vs. ambiguous
- Explicitly test and refute (or confirm) the benign hypothesis
- State the single strongest evidence FOR intentional destruction
- State the single strongest uncertainty or counterargument
- Explain WHY you chose to question (if asking) or conclude directly (if not)

## Output Format

You MUST output your response in exactly two parts:
1. A <think>...</think> block containing your step-by-step reasoning.
2. A ```json code block containing your structured output.
"""

_OPEN_CHOICE_SCHEMA = """
---
DECISION POINT: You may now either ask a clarifying question OR render your verdict.

Choose QUESTION only if: missing context would change your score by 20+ points AND the
question is specific and one-sentence answerable. Otherwise choose VERDICT.

QUESTION SCHEMA:
```json
{
  "type": "question",
  "question": "<specific, forensically actionable question — one sentence>",
  "reasoning": "<one sentence: which signal is ambiguous and how the answer shifts your score>"
}
```

VERDICT SCHEMA:
```json
{
  "type": "verdict",
  "score": <float 0.0-100.0>,
  "hypothesis": "<2-3 sentence narrative: name the signals, state your conclusion>",
  "confidence": "<LOW|MEDIUM|HIGH|VERY HIGH>",
  "risk_level": "<MINIMAL|POSSIBLE|PROBABLE|CRITICAL>",
  "evidence_chain": [
    "<Signal name: what it shows and why it matters for intent>",
    "<Signal name: what it shows and why it matters for intent>",
    "<Signal name: what it shows and why it matters for intent>"
  ],
  "investigator_questions": [
    "<Follow-up question for human investigators to pursue outside this system>",
    "<Follow-up question for human investigators to pursue outside this system>"
  ]
}
```
"""

_MUST_GIVE_VERDICT_SCHEMA = """
---
You have gathered sufficient investigator context. You MUST now render your final verdict.

VERDICT SCHEMA:
```json
{
  "type": "verdict",
  "score": <float 0.0-100.0>,
  "hypothesis": "<2-3 sentence narrative: name the signals, incorporate human answers, state your conclusion>",
  "confidence": "<LOW|MEDIUM|HIGH|VERY HIGH>",
  "risk_level": "<MINIMAL|POSSIBLE|PROBABLE|CRITICAL>",
  "evidence_chain": [
    "<Signal name: what it shows and why it matters for intent>",
    "<Signal name: what it shows and why it matters for intent>",
    "<Signal name: what it shows and why it matters for intent>"
  ],
  "investigator_questions": [
    "<Follow-up question for human investigators to pursue outside this system>",
    "<Follow-up question for human investigators to pursue outside this system>"
  ]
}
```
"""


# ---------------------------------------------------------------------------
# PipelineAgent
# ---------------------------------------------------------------------------

class PipelineAgent:
    """
    Executes deep forensic reasoning during the scan pipeline.

    On each scan, the agent:
      1. Receives a structured crime_scene_data dict of heuristic signals
      2. Reasons through the evidence in a <think> block (streams to Activity Log)
      3. Optionally asks the investigator 1-2 targeted clarifying questions (HITL)
      4. Renders a verdict with score, hypothesis, evidence_chain, and follow-up questions
    """

    def __init__(
        self,
        groq_client: Groq | None = None,
        agent_thought_callback=None,
        agent_question_callback=None,
    ):
        self._client = groq_client or Groq(api_key=config.groq_api_key)
        self._model = config.models.intent
        self.agent_thought_callback = agent_thought_callback
        # Signature: agent_question_callback(question: str, reasoning: str) -> str
        self.agent_question_callback = agent_question_callback

    def _think(self, text: str) -> None:
        """Emit a thought to the activity log callback."""
        if self.agent_thought_callback:
            self.agent_thought_callback(text)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze_intent(self, crime_scene_data: dict) -> dict:
        """
        Run the full forensic reasoning loop.

        Returns a dict with: score, hypothesis, confidence, risk_level,
        evidence_chain, investigator_questions.
        Returns {} if no valid Groq API key or on fatal error.
        """
        if not config.groq_api_key or config.groq_api_key.startswith("gsk_..."):
            logger.warning("[PipelineAgent] No valid Groq API key. Skipping AI analysis.")
            return {}

        self._think("Initiating forensic signal analysis...")
        prompt = self._build_intent_prompt(crime_scene_data)
        messages = [{"role": "user", "content": prompt}]

        questions_asked = 0
        no_callback_notified = False

        for turn in range(_MAX_TURNS):
            can_ask = questions_asked < _MAX_QUESTIONS

            if can_ask:
                self._think(
                    f"Correlating evidence signals (turn {turn + 1}) — "
                    f"testing hypotheses and deciding whether clarification is needed..."
                )
                current_system = _BASE_INSTRUCTION + _OPEN_CHOICE_SCHEMA
            else:
                self._think(
                    f"Sufficient context gathered. Rendering final forensic verdict..."
                )
                current_system = _BASE_INSTRUCTION + _MUST_GIVE_VERDICT_SCHEMA

            turn_messages = [{"role": "system", "content": current_system}] + messages

            response_json = self._stream_and_parse_with_retry(turn_messages, turn)
            if response_json is None:
                # Fatal error already surfaced to activity log inside the method
                return {}

            if not response_json:
                self._think(
                    f"Response on turn {turn + 1} had no parseable JSON — "
                    f"prompting model to retry with required format..."
                )
                logger.warning(f"[PipelineAgent] Empty/invalid response on turn {turn + 1}")
                # Push the model with an explicit reminder to use the JSON schema
                messages.append({
                    "role": "user",
                    "content": (
                        "[System: Your last response did not contain valid JSON output. "
                        "Please provide your complete response using the required JSON schema above. "
                        "Include a <think> reasoning block followed by the ```json block.]"
                    ),
                })
                continue

            msg_type = response_json.get("type", "verdict")

            # ---- Question ----
            if msg_type == "question":
                question = response_json.get("question", "Need more context.")
                reasoning = response_json.get("reasoning", "")
                questions_asked += 1

                self._think(
                    f"Identified ambiguity — pausing to request investigator context: {question}"
                )

                if not self.agent_question_callback:
                    if not no_callback_notified:
                        logger.warning(
                            "[PipelineAgent] Agent wants to ask a question but no "
                            "HITL callback is registered. Forcing verdict on next turn."
                        )
                        no_callback_notified = True
                    # Force verdict immediately — add a note so the model knows
                    messages.append({
                        "role": "assistant",
                        "content": (
                            f"<think>I wanted to ask: {question} "
                            f"(reasoning: {reasoning}) but no human is available.</think>\n"
                            f"```json\n{json.dumps(response_json)}\n```"
                        ),
                    })
                    messages.append({
                        "role": "user",
                        "content": (
                            "[System note: No human investigator is available to answer questions. "
                            "Please render your best-effort verdict based on the available signals alone, "
                            "noting the unresolved ambiguity in your hypothesis.]"
                        ),
                    })
                    # Force verdict next turn regardless of questions_asked
                    questions_asked = _MAX_QUESTIONS
                    continue

                # Block the scan thread waiting for the investigator's answer
                human_answer = self.agent_question_callback(question, reasoning)
                self._think(f"Investigator responded: {human_answer}")

                # Append the Q/A exchange to conversation history
                messages.append({
                    "role": "assistant",
                    "content": (
                        f"<think>Waiting for investigator context...</think>\n"
                        f"```json\n{json.dumps(response_json)}\n```"
                    ),
                })
                messages.append({
                    "role": "user",
                    "content": f"[Investigator context]: {human_answer}",
                })
                continue

            # ---- Verdict ----
            elif msg_type == "verdict":
                self._think(
                    f"Forensic assessment complete — "
                    f"score={response_json.get('score', '?')}, "
                    f"risk={response_json.get('risk_level', '?')}"
                )
                response_json.pop("type", None)
                return response_json

        self._think("Reached maximum reasoning turns without a conclusive verdict.")
        return {}

    # ------------------------------------------------------------------
    # Groq streaming + JSON extraction
    # ------------------------------------------------------------------

    def _stream_and_parse_with_retry(self, messages: list, turn: int) -> dict | None:
        """
        Calls _stream_and_parse with retry logic for transient Groq errors.

        Returns:
            dict  — parsed JSON response (may be {} if model gave no JSON)
            None  — fatal error after all retries exhausted
        """
        last_exc = None
        for attempt in range(_MAX_RETRIES):
            try:
                result = self._stream_and_parse(messages)
                return result
            except Exception as exc:
                last_exc = exc
                exc_type = type(exc).__name__
                exc_msg = str(exc)[:200]

                # Log full traceback to server stderr for debugging
                print(
                    f"[PipelineAgent] Turn {turn + 1}, attempt {attempt + 1}/{_MAX_RETRIES} "
                    f"failed: {exc_type}: {exc_msg}\n{traceback.format_exc()}",
                    file=sys.stderr,
                )

                # Surface human-readable error in the Activity Log
                if attempt == 0:
                    # First failure: show the actual exception type so it's diagnosable
                    self._think(
                        f"⚠ Analysis interrupted ({exc_type}): {exc_msg[:120]}. "
                        f"Retrying ({attempt + 2}/{_MAX_RETRIES})..."
                    )

                # Check if this is a rate-limit or server error (worth retrying)
                is_retryable = any(
                    kw in exc_type.lower() or kw in exc_msg.lower()
                    for kw in ("ratelimit", "rate_limit", "429", "503", "timeout",
                               "connection", "network", "internal")
                )
                if is_retryable and attempt < _MAX_RETRIES - 1:
                    wait = 2 ** attempt  # 1s, 2s, 4s
                    self._think(f"Retrying in {wait}s (transient API error)...")
                    time.sleep(wait)
                elif not is_retryable:
                    # Non-retryable error (e.g., auth, invalid request)
                    self._think(
                        f"⚠ Non-retryable error ({exc_type}). "
                        f"Falling back to rule-based analysis."
                    )
                    return None

        # All retries exhausted
        self._think(
            f"⚠ Analysis failed after {_MAX_RETRIES} attempts. "
            f"Last error: {type(last_exc).__name__}: {str(last_exc)[:100]}. "
            f"Falling back to rule-based analysis."
        )
        return None

    def _stream_and_parse(self, messages: list) -> dict:
        """
        Stream a Groq response, extract and stream <think> sentences live,
        then extract and parse the final ```json block.

        Raises on Groq API errors (caller handles retry).
        Returns {} if the model produced no parseable JSON (not an error).
        """
        response_stream = self._client.chat.completions.create(
            model=self._model,
            messages=messages,
            temperature=0.3,      # deterministic forensic reasoning
            max_tokens=_MAX_TOKENS,
            stream=True,
        )

        full_response = ""
        in_think_block = False
        think_block_done = False   # FIX: prevent re-entering after </think>
        emitted_length = 0

        for chunk in response_stream:
            # FIX: guard against final empty-choices chunk from Groq
            if not chunk.choices:
                continue
            delta = chunk.choices[0].delta
            if delta is None:
                continue
            token = delta.content or ""
            full_response += token

            # Detect <think> entry (only if not already completed a think block)
            if not in_think_block and not think_block_done and "<think>" in full_response:
                in_think_block = True
                continue

            # Detect </think> exit
            if in_think_block and "</think>" in full_response:
                in_think_block = False
                think_block_done = True   # FIX: mark think block as permanently done
                # Emit any remaining unemitted content from the think block
                think_content = full_response.split("<think>", 1)[1].split("</think>", 1)[0]
                remaining = think_content[emitted_length:].strip()
                if remaining:
                    self._think(remaining)
                emitted_length = 0
                continue

            # Stream think block content sentence by sentence
            if in_think_block:
                think_content = full_response.split("<think>", 1)[1]
                unemitted = think_content[emitted_length:]
                # Match a complete sentence (ending with . ! ?)
                match = re.search(r"(.*?[.!?])(?:\s)", unemitted, re.DOTALL)
                if match:
                    stmt = match.group(1).strip()
                    if stmt and len(stmt) > 10:   # skip very short fragments
                        self._think(stmt)
                    emitted_length += len(match.group(0))

        # --- JSON extraction ---
        # Primary: fenced ```json ... ``` block (most reliable)
        json_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", full_response, re.DOTALL)
        if json_match:
            json_text = json_match.group(1)
        else:
            # Fallback: find the outermost { ... } using a balanced scan
            json_text = self._extract_outermost_json(full_response)

        try:
            return json.loads(json_text)
        except json.JSONDecodeError as exc:
            logger.warning(
                f"[PipelineAgent] JSON decode failed: {exc}. "
                f"Raw snippet: {json_text[:300]!r}"
            )
            self._think(f"⚠ Response JSON was malformed (truncated response?). Retrying...")
            return {}   # signal to caller to retry

    @staticmethod
    def _extract_outermost_json(text: str) -> str:
        """
        Extract the outermost balanced JSON object from text using brace counting.
        More robust than a greedy regex for nested/complex JSON.
        Returns '{}' if nothing found.
        """
        start = text.find("{")
        if start == -1:
            return "{}"
        depth = 0
        in_str = False
        escape_next = False
        for i, ch in enumerate(text[start:], start=start):
            if escape_next:
                escape_next = False
                continue
            if ch == "\\" and in_str:
                escape_next = True
                continue
            if ch == '"':
                in_str = not in_str
            if not in_str:
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        return text[start: i + 1]
        return "{}"

    # ------------------------------------------------------------------
    # Evidence prompt builder
    # ------------------------------------------------------------------

    def _build_intent_prompt(self, data: dict) -> str:
        """
        Build a rich, interpretive forensic evidence summary for the LLM.
        Includes signal values, contextual framing, and conditional interpretation notes.
        """
        wiped = data.get("wiped_clusters", 0)
        total = data.get("total_clusters", 0)
        pct = (wiped / total * 100) if total else 0.0
        scope = data.get("wipe_scope", "unknown")
        is_local = data.get("is_localized", False)
        dirs = data.get("targeted_dirs", [])
        intensity = data.get("intensity", 0.0) * 100
        temporal = data.get("temporal_correlation", False)
        sensitive = data.get("sensitive_targeted", False)

        # Locality description
        if is_local and dirs:
            locality_desc = f"Targeted — confined to {len(dirs)} specific path(s)"
        elif is_local:
            locality_desc = "Targeted — localized region (no directory names extracted)"
        else:
            locality_desc = "Broad — full-disk or partition-wide coverage"

        # Targeted paths
        dir_display = ", ".join(f'"{d}"' for d in dirs[:5]) if dirs else "None identified"

        # Hidden volume section
        hv_count = data.get("hidden_volume_count", 0)
        hv_max_conf = data.get("hidden_volume_max_confidence", 0.0)
        hv_hints = data.get("hidden_volume_tool_hints", [])
        if hv_count > 0:
            hv_section = (
                f"\nHidden Encrypted Volume Signals:\n"
                f"  Candidates Detected:   {hv_count}\n"
                f"  Highest Confidence:    {hv_max_conf * 100:.1f}%\n"
                f"  Suspected Tool(s):     {', '.join(hv_hints) if hv_hints else 'Unknown'}\n"
                f"  Forensic Note:         Plausible deniability architecture detected. "
                f"The suspect may have hidden data inside an outer volume that appears "
                f"legitimate. This is a sophisticated anti-forensics technique almost "
                f"never seen in accidental or routine disk operations."
            )
        else:
            hv_section = "\nHidden Encrypted Volume Signals:\n  None detected."

        # Conditional interpretation notes
        notes: list[str] = []
        if scope == "selective" and sensitive and temporal:
            notes.append(
                "STRONG PATTERN: Selective scope + sensitive directory targeting + "
                "temporal correlation = classic deliberate cover-up sequence. "
                "This combination is rarely seen in authorized IT operations."
            )
        elif scope == "selective" and sensitive:
            notes.append(
                "HIGH SUSPICION: Selective wipe of sensitive directories suggests "
                "the perpetrator knew specifically which data to destroy."
            )
        elif scope == "full_disk" and not temporal and not sensitive:
            notes.append(
                "AMBIGUOUS: Full-disk wipe without temporal correlation or sensitive "
                "targeting could indicate authorized IT decommissioning. "
                "Contextual confirmation is valuable here."
            )
        if hv_count > 0 and hv_max_conf >= 0.6:
            notes.append(
                "CRITICAL SIGNAL: Hidden encrypted volumes at high confidence are a "
                "near-definitive indicator of intentional data concealment. "
                "Treat as CRITICAL regardless of other signals."
            )
        if intensity < 30:
            notes.append(
                "LOW INTENSITY NOTE: Wipe detections have low confidence scores. "
                "Consider whether this may be a false positive or very minor operation."
            )
        if pct < 5.0 and not sensitive and not temporal:
            notes.append(
                "SMALL FOOTPRINT: Less than 5% of disk affected with no sensitive targeting "
                "or temporal correlation — could be routine OS maintenance or minor deletion."
            )

        notes_section = ""
        if notes:
            notes_section = "\nInterpretation Notes:\n" + "\n".join(f"  - {n}" for n in notes)

        return f"""FORENSIC EVIDENCE SUMMARY
==========================
Disk Coverage:
  Wipe Scope:           {scope}
  Wiped / Total:        {wiped:,} of {total:,} clusters  ({pct:.1f}% of disk)
  Locality:             {locality_desc}
  Targeted Paths:       {dir_display}
  Wipe Intensity:       {intensity:.0f}%  (mean confidence of wipe signature matches)

Behavioral Signals:
  Temporal Correlation: {"YES — wipe activity follows mass file deletion events" if temporal else "No"}
  Sensitive Dir Hit:    {"YES — high-value directories targeted" if sensitive else "No"}
{hv_section}
{notes_section}

Your task: Apply your 4-step methodology to this evidence. Reason thoroughly in your
<think> block, then output the required JSON schema.
"""
