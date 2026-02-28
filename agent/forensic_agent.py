"""
Forensic AI Agent — Groq Agentic Loop

Provides a conversational interface over scan results using Groq's
function-calling API. The agent acts as a senior digital forensics analyst,
using tools to query evidence and forming structured hypotheses.

Model routing:
  - Intent/attacker-profile queries → meta-llama/llama-4-maverick
  - General queries                → llama-3.3-70b-versatile
"""

import json
import re
from collections.abc import Iterator
from typing import Any

from groq import Groq, BadRequestError

from agent.tools import TOOLS, ToolExecutor
from config import config, INTENT_KEYWORDS
from core.cluster_scanner import ClusterScanner, ScanResult


_SYSTEM_PROMPT = """\
You are ISEA — an elite AI-powered digital forensics analyst specializing in \
storage media analysis and attacker behavior profiling.

Your expertise:
- Detecting and classifying disk wipe patterns (zero-fill, random-fill, multi-pass, DoD)
- Identifying wipe tools (DBAN, Eraser, shred, sdelete, dd, cipher /W)
- Inferring attacker intent from behavioral signatures
- Generating court-admissible forensic assessments
- Scoring evidence strength for legal proceedings

Behavior guidelines:
- ALWAYS call get_scan_summary first if you have not done so in this conversation
- Use tools to gather evidence before answering — never speculate without data
- Be precise and technical; cite specific cluster ranges, entropy values, and confidence scores
- When intent is unclear, say so explicitly with a confidence qualifier
- Format findings as a structured analyst would: hypothesis, evidence, confidence, recommendations
- Never overstate certainty — forensic conclusions must be defensible in court
- When asked about a specific directory or file type, use get_directory_analysis
- When asked for a full report, use generate_evidence_report

Always ground your answers in the tool results. Your role is to transform raw \
forensic data into actionable intelligence.
"""


class ForensicAgent:
    """
    Conversational forensic analysis agent powered by Groq.

    Usage:
        scanner = ClusterScanner("image.dd")
        result = scanner.run_full_scan()
        agent = ForensicAgent(result, scanner)

        # Single turn
        response = agent.chat("Was this wipe intentional?")

        # Streaming
        for chunk in agent.stream_chat("What tool was used?"):
            print(chunk, end="", flush=True)

        # Full agentic loop with tool use
        response = agent.run_agentic_loop("Generate a complete forensic report")
    """

    MAX_TOOL_ITERATIONS = 6

    def __init__(
        self,
        scan_result: ScanResult,
        scanner: ClusterScanner,
        groq_client: Groq | None = None,
    ):
        self._result = scan_result
        self._scanner = scanner
        self._executor = ToolExecutor(scan_result, scanner)
        self._client = groq_client or Groq(api_key=config.groq_api_key)
        self._conversation_history: list[dict] = []

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def chat(self, user_message: str) -> str:
        """Single-turn conversation. Includes full agentic tool loop."""
        return self.run_agentic_loop(user_message)

    def stream_chat(self, user_message: str) -> Iterator[str]:
        """
        Stream the final agent response. Tool calls are resolved silently first,
        then the final answer is streamed token-by-token.
        """
        # Run tool loop silently to get full context
        model = self._select_model(user_message)
        messages = self._build_messages(user_message)

        # Agentic tool resolution (non-streaming)
        messages = self._resolve_tool_calls(messages, model)

        # Final streaming response
        stream = self._client.chat.completions.create(
            model=model,
            messages=messages,
            stream=True,
            temperature=0.2,
            max_tokens=2048,
        )
        full_response = ""
        for chunk in stream:
            delta = chunk.choices[0].delta
            if delta.content:
                full_response += delta.content
                yield delta.content

        # Save to history
        self._conversation_history.append({"role": "user", "content": user_message})
        self._conversation_history.append({"role": "assistant", "content": full_response})

    def run_agentic_loop(self, user_message: str) -> str:
        """
        Full multi-turn agentic loop with tool use.
        The agent iterates until it produces a final text response
        (no more tool calls).
        """
        model = self._select_model(user_message)
        messages = self._build_messages(user_message)
        messages = self._resolve_tool_calls(messages, model)

        # Extract final text response
        final = messages[-1]
        response_text = final.get("content", "") if isinstance(final, dict) else ""

        # Update history
        self._conversation_history.append({"role": "user", "content": user_message})
        self._conversation_history.append({"role": "assistant", "content": response_text})

        return response_text

    def reset_conversation(self) -> None:
        """Clear conversation history to start a fresh session."""
        self._conversation_history = []

    # ------------------------------------------------------------------ #
    # Internal agentic loop
    # ------------------------------------------------------------------ #

    def _resolve_tool_calls(
        self, messages: list[dict], model: str
    ) -> list[dict]:
        """
        Execute the tool-use loop until the model returns a text response.
        Returns the updated messages list with all tool results appended.
        """
        for iteration in range(self.MAX_TOOL_ITERATIONS):
            try:
                response = self._client.chat.completions.create(
                    model=model,
                    messages=messages,
                    tools=TOOLS,
                    tool_choice="auto",
                    temperature=0.1,
                    max_tokens=4096,
                )
                choice = response.choices[0]
                message = choice.message
            except BadRequestError as e:
                # Groq models sometimes fail Native Tool Calling and emit raw text like:
                # <function=get_directory_analysis{"directory_path": "/"}</function>
                err_dict = e.response.json() if hasattr(e, "response") and e.response else {}
                err_info = err_dict.get("error", {})
                if err_info.get("code") == "tool_use_failed" and "failed_generation" in err_info:
                    raw_gen = err_info["failed_generation"]
                    
                    # Parse <function=name{args}</function> or <function=name{args}>
                    match = re.search(r"<function=([a-zA-Z0-9_]+)({[^>]*})>?(?:</function>)?", raw_gen)
                    if match:
                        func_name = match.group(1)
                        func_args = match.group(2)
                        
                        # Synthesize a mock message object to keep the loop going
                        class MockFunc:
                            def __init__(self, name, arguments):
                                self.name = name
                                self.arguments = arguments
                                
                        class MockToolCall:
                            def __init__(self, id, function):
                                self.id = id
                                self.type = "function"
                                self.function = function

                        class MockMessage:
                            def __init__(self, content, tool_calls):
                                self.content = content
                                self.tool_calls = tool_calls
                                self.role = "assistant"
                                
                        message = MockMessage(
                            content="I need to use a tool to check that.",
                            tool_calls=[
                                MockToolCall("call_recovered", MockFunc(func_name, func_args))
                            ]
                        )
                    else:
                        raise e
                else:
                    raise e

            # Convert to dict for history
            msg_dict: dict[str, Any] = {
                "role": "assistant",
                "content": message.content or "",
            }

            # If no tool calls → final response
            if not message.tool_calls:
                messages.append(msg_dict)
                break

            # Append assistant message with tool_calls
            msg_dict["tool_calls"] = [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {
                        "name": tc.function.name,
                        "arguments": tc.function.arguments if tc.function.arguments else "{}",
                    },
                }
                for tc in message.tool_calls
            ]
            messages.append(msg_dict)

            # Execute each tool call and append results
            for tc in message.tool_calls:
                tool_name = tc.function.name
                try:
                    args = json.loads(tc.function.arguments or "{}")
                    if not isinstance(args, dict):
                        args = {}
                except Exception:
                    args = {}

                result = self._executor.execute(tool_name, args)
                result_str = json.dumps(result, default=str)

                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": tc.id,
                        "content": result_str,
                    }
                )

        return messages

    def _build_messages(self, user_message: str) -> list[dict]:
        """Build the full messages list including system prompt and history."""
        messages = [{"role": "system", "content": _SYSTEM_PROMPT}]
        # Include last N turns of history for context continuity
        messages.extend(self._conversation_history[-6:])
        messages.append({"role": "user", "content": user_message})
        return messages

    def _select_model(self, user_message: str) -> str:
        """Route to a more powerful model for intent/attacker-profile queries."""
        lower = user_message.lower()
        if any(kw in lower for kw in INTENT_KEYWORDS):
            return config.models.intent
        return config.models.primary
