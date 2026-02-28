"""
Pipeline Agent — Synchronous In-Scan AI Analysis

Unlike the ForensicAgent which handles open-ended chat, the PipelineAgent
is embedded directly into the ISEA scanning pipeline. It makes synchronous,
structured calls to the Groq LLM to perform deterministic forensic reasoning
(e.g., deducing intent, classifying tools) mid-scan.
"""

import json
import logging
import re
from typing import Any

from groq import Groq
from config import config

logger = logging.getLogger(__name__)


class PipelineAgent:
    """
    Executes focused, structured AI analysis during the scan pipeline.
    """

    def __init__(self, groq_client: Groq | None = None, agent_thought_callback=None, agent_question_callback=None):
        self._client = groq_client or Groq(api_key=config.groq_api_key)
        self._model = config.models.intent
        self.agent_thought_callback = agent_thought_callback
        self.agent_question_callback = agent_question_callback

    def _think(self, text: str):
        if self.agent_thought_callback:
            self.agent_thought_callback(text)

    def analyze_intent(self, crime_scene_data: dict) -> dict:
        """
        Analyze raw heuristic evidence and deduce attacker intent.
        Optionally asks the human for context before rendering a final verdict.
        """
        if not config.groq_api_key or config.groq_api_key == "gsk_...":
            logger.warning("No valid Groq API key found. Skipping AI Intent Analysis.")
            return {}

        self._think("Analyzing crime scene metrics (locality, temporal correlations)...")
        prompt = self._build_intent_prompt(crime_scene_data)

        # 1. Base instruction ruleset
        base_instruction = (
            "You are the ISEA core intent analysis engine. "
            "You receive raw forensic evidence about disk wipe activity. "
            "Your job is to deduce the attacker's intent, calculate an evidence "
            "score (0.0 to 100.0), and assign a risk level (MINIMAL, POSSIBLE, PROBABLE, CRITICAL). "
            "You MUST output your response in two strict parts:\n\n"
            "1. First, a <think> block where you reason through the evidence step-by-step "
            "like a human forensic analyst thinking aloud.\n"
            "2. Second, a markdown JSON block containing your output.\n\n"
        )
        
        question_schema = (
            "CRITICAL HUMAN-IN-THE-LOOP INSTRUCTION:\n"
            "You MUST ask the human investigator 1 clarifying question about the context of the wipe to help formulate your final verdict (e.g. 'Was this wipe authorized by IT?').\n"
            "Output ONLY the following Question schema:\n"
            "```json\n"
            "{\n"
            '  "type": "question",\n'
            '  "question": "<string containing your specific question>"\n'
            "}\n"
            "```"
        )
        
        verdict_schema = (
            "Only when the human HAS provided an answer in the chat history, you MUST output the Verdict schema:\n"
            "```json\n"
            "{\n"
            '  "type": "verdict",\n'
            '  "score": <float>,\n'
            '  "hypothesis": "<string explaining the deduction incorporating the human answer>",\n'
            '  "confidence": "<LOW|MEDIUM|HIGH|VERY HIGH>",\n'
            '  "risk_level": "<string>"\n'
            "}\n"
            "```"
        )

        messages = [
            {"role": "user", "content": prompt}
        ]

        # Multi-turn Human-in-the-Loop Interaction Loop
        max_turns = 4
        for turn in range(max_turns):
            if turn == 0:
                self._think("Consulting Groq LLM to deduce attacker intent and formulate hypothesis...")
                # Force Question Schema
                current_system = base_instruction + question_schema
            else:
                self._think(f"Re-evaluating evidence with new human context (turn {turn+1})...")
                # Force Verdict Schema
                current_system = base_instruction + verdict_schema

            # Prepend the system prompt for this specific turn
            turn_messages = [{"role": "system", "content": current_system}] + messages

            try:
                response_json = self._stream_and_parse(turn_messages)
            except Exception as e:
                logger.error(f"[PipelineAgent] Groq API or Parse error: {e}")
                self._think("An error occurred during evidence evaluation.")
                return {}

            if not response_json:
                return {}

            msg_type = response_json.get("type", "verdict")

            if msg_type == "question":
                question = response_json.get("question", "Need more context.")
                self._think(f"Pausing analysis to request human context: {question}")
                
                # If no callback exists, just force a verdict logic
                if not self.agent_question_callback:
                    logger.warning("[PipelineAgent] AI asked a question but no callback was provided.")
                    # Fallback to an empty verdict
                    return {
                        "score": 50.0,
                        "hypothesis": "Evidence was ambiguous. Analysis aborted due to missing human-in-the-loop bridge.",
                        "confidence": "LOW",
                        "risk_level": "POSSIBLE"
                    }

                # Block the thread waiting for the human
                human_answer = self.agent_question_callback(question)
                self._think(f"Received human input: {human_answer}")
                
                # Add context to history and run loop again
                messages.append({
                    "role": "assistant",
                    "content": f"<think>Waiting for human...</think>\n```json\n{json.dumps(response_json)}\n```"
                })
                messages.append({
                    "role": "user",
                    "content": f"[Human Investigator context]: {human_answer}"
                })
                continue

            elif msg_type == "verdict":
                self._think("Intent Assessment finalized successfully.")
                # We strip "type" before returning it to keep it clean for downstream core/intent_modeler.py
                response_json.pop("type", None)
                return response_json

        self._think("Hit maximum interrogation turns without reaching a conclusion.")
        return {}


    def _stream_and_parse(self, messages: list) -> dict:
        """
        Helper method to isolate the SSE stream processing block.
        """
        response_stream = self._client.chat.completions.create(
            model=self._model,
            messages=messages,
            temperature=0.3, # Keep determinism high
            max_tokens=800,
            stream=True
        )

        full_response = ""
        in_think_block = False
        emitted_length = 0

        for chunk in response_stream:
            token = chunk.choices[0].delta.content or ""
            full_response += token
            
            # State machine
            if "<think>" in full_response and not in_think_block:
                in_think_block = True
                continue
            
            if "</think>" in full_response and in_think_block:
                in_think_block = False
                
                # Emit any remaining text in the think block
                think_content = full_response.split("<think>")[-1].split("</think>")[0]
                remaining = think_content[emitted_length:].strip()
                if remaining:
                    self._think(remaining)
                continue

            if in_think_block:
                think_content = full_response.split("<think>")[-1]
                # We look at the delta of what hasn't been emitted yet
                unemitted = think_content[emitted_length:]
                
                # If we have a complete sentence ending in punctuation and a space/newline
                match = re.search(r'(.*?[.!?])(?: |\n)', unemitted, re.DOTALL)
                if match:
                    stmt = match.group(1).strip()
                    if stmt:
                        self._think(stmt)
                    emitted_length += len(match.group(0))

        # Post-process full string for the JSON payload
        json_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', full_response, re.DOTALL)
        if json_match:
            json_text = json_match.group(1)
        else:
            # Fallback if the strict ```json wasn't used but the block exists
            json_match = re.search(r'(\{.*\})', full_response, re.DOTALL)
            json_text = json_match.group(1) if json_match else "{}"
            
        return json.loads(json_text)

    def _build_intent_prompt(self, data: dict) -> str:
        """Formats the heuristic data into a crime scene summary for the LLM."""
        return f"""
Analyze the following forensic crime scene data:

Wipe Evidence:
- Wipe Scope: {data.get('wipe_scope', 'unknown')}
- Is Localized: {data.get('is_localized', False)}
- Targeted Directories: {', '.join(data.get('targeted_dirs', [])) or 'None identified'}
- Intensity/Completeness: {data.get('intensity', 0.0) * 100:.1f}%

Contextual Metadata:
- Temporal Correlation (wipes follow file deletions): {data.get('temporal_correlation', False)}
- Sensitive Directories Targeted: {data.get('sensitive_targeted', False)}
- Total Wiped Clusters: {data.get('wiped_clusters', 0)} of {data.get('total_clusters', 0)}

Task:
Based *only* on the signals above, output the required JSON assessment. 
If there is no temporal correlation and no sensitive targeting for a small localized wipe, the risk is likely MINIMAL.
If specific sensitive directories were targeted immediately after deletion, that implies a PROBABLE or CRITICAL intentional cover-up.
"""
