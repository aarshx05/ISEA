"""
Wipe Signature Matching Engine

Compares cluster-level analysis results against known wipe tool profiles
to identify the most likely wipe tool and algorithm used by an attacker.
"""

import json
from pathlib import Path
from typing import Any

from core.entropy_engine import EntropyEngine


_DEFAULT_PROFILES = Path(__file__).parent / "tool_profiles.json"


class SignatureMatcher:
    """
    Matches entropy/pattern analysis results against the tool signature database.
    Ranks candidate tools by confidence and returns structured classification.
    """

    def __init__(self, profiles_path: str | Path = _DEFAULT_PROFILES):
        self.profiles_path = Path(profiles_path)
        self._profiles: list[dict] = []
        self._engine = EntropyEngine()
        self.load_profiles()

    def load_profiles(self) -> None:
        with open(self.profiles_path, "r") as f:
            data = json.load(f)
        self._profiles = data.get("tools", [])

    # ------------------------------------------------------------------ #
    # Per-cluster matching
    # ------------------------------------------------------------------ #

    def match_cluster(self, classification: dict) -> list[dict]:
        """
        Given a single cluster's classification dict (from EntropyEngine.classify_region),
        return a ranked list of tool matches.

        Returns list of:
        {
            "tool_id":    str,
            "tool_name":  str,
            "score":      float,   # 0.0–1.0
            "algorithm":  str | None,
            "reason":     str
        }
        sorted by score descending.
        """
        entropy = classification.get("entropy", 0.0)
        fill_byte = classification.get("fill_byte")
        is_random = classification.get("is_random", False)
        cls_label = classification.get("classification", "natural_residual")

        matches: list[dict] = []

        for tool in self._profiles:
            sig = tool.get("entropy_signature", {})
            dom_low, dom_high = sig.get("dominant_range", [0.0, 8.0])
            allows_uniform = sig.get("allows_uniform_fill", False)
            expected_fill_byte = sig.get("fill_byte")
            consistency_range = sig.get("overwrite_consistency", [0.0, 1.0])

            score = 0.0
            reasons = []

            # Entropy range match
            if dom_low <= entropy <= dom_high:
                band = dom_high - dom_low
                center = (dom_low + dom_high) / 2
                proximity = 1.0 - abs(entropy - center) / max(band / 2, 0.01)
                score += proximity * 0.5
                reasons.append(f"entropy {entropy:.2f} in expected range [{dom_low}–{dom_high}]")

            # Fill byte match
            if expected_fill_byte and fill_byte is not None:
                expected_int = int(expected_fill_byte, 16)
                if fill_byte == expected_int:
                    score += 0.25
                    reasons.append(f"fill byte 0x{fill_byte:02X} matches signature")
            elif allows_uniform and fill_byte is not None:
                score += 0.1
                reasons.append("uniform fill consistent with tool")

            # Classification alignment
            if cls_label in ("intentional_wipe", "secure_erase") and dom_low >= 5.5:
                score += 0.15
            elif cls_label in ("natural_residual", "os_clear") and dom_high < 5.0:
                score += 0.1

            # Random fill indicator
            if is_random and not sig.get("fill_byte") and not allows_uniform:
                score += 0.1
                reasons.append("random fill pattern consistent with tool")

            if score > 0.1:
                # Find best-matching algorithm
                algo_name = self._best_algorithm(tool, entropy, fill_byte)
                matches.append(
                    {
                        "tool_id": tool["id"],
                        "tool_name": tool["name"],
                        "score": round(min(score, 1.0), 4),
                        "algorithm": algo_name,
                        "reason": "; ".join(reasons) if reasons else "partial match",
                    }
                )

        matches.sort(key=lambda x: x["score"], reverse=True)
        return matches

    def _best_algorithm(
        self, tool: dict, entropy: float, fill_byte: int | None
    ) -> str | None:
        """Return the name of the most likely algorithm for a tool given the evidence."""
        algorithms = tool.get("algorithms", [])
        if not algorithms:
            return None
        if len(algorithms) == 1:
            return algorithms[0]["name"]

        # Score each algorithm
        best_name = algorithms[0]["name"]
        best_score = -1.0
        for algo in algorithms:
            score = 0.0
            algo_range = algo.get("entropy_range", algo.get("final_entropy_range", [0.0, 8.0]))
            if isinstance(algo_range, list) and len(algo_range) == 2:
                if algo_range[0] <= entropy <= algo_range[1]:
                    score += 1.0
            seq = algo.get("sequence", [])
            for step in seq:
                expected_byte = step.get("byte")
                if expected_byte and fill_byte is not None:
                    if int(expected_byte, 16) == fill_byte:
                        score += 0.5
            if score > best_score:
                best_score = score
                best_name = algo["name"]
        return best_name

    # ------------------------------------------------------------------ #
    # Region-level analysis
    # ------------------------------------------------------------------ #

    def classify_wipe_algorithm(self, region_analyses: list[dict]) -> dict:
        """
        Given a list of cluster classification dicts for a contiguous region,
        determine the most likely wipe tool and algorithm.

        Returns:
        {
            "tool":          str,
            "tool_id":       str,
            "algorithm":     str,
            "pass_count":    int,
            "confidence":    float,
            "evidence":      list[str],
            "runner_up":     str | None
        }
        """
        if not region_analyses:
            return self._unknown_result("No cluster data provided")

        # Aggregate scores across clusters (with subsampling for performance)
        MAX_SAMPLES = 500
        if len(region_analyses) > MAX_SAMPLES:
            step = len(region_analyses) // MAX_SAMPLES
            sampled_analyses = region_analyses[::step][:MAX_SAMPLES]
        else:
            sampled_analyses = region_analyses

        tool_scores: dict[str, list[float]] = {}
        tool_algorithms: dict[str, list[str | None]] = {}
        evidence_set: set[str] = set()

        for analysis in sampled_analyses:
            matches = self.match_cluster(analysis)
            for m in matches[:3]:  # top 3 per cluster
                tid = m["tool_id"]
                if tid not in tool_scores:
                    tool_scores[tid] = []
                    tool_algorithms[tid] = []
                tool_scores[tid].append(m["score"])
                tool_algorithms[tid].append(m["algorithm"])
                if m["reason"]:
                    evidence_set.add(m["reason"].split(";")[0])  # first reason only

        if not tool_scores:
            return self._unknown_result("No significant wipe signatures detected")

        # Winner: highest mean score across clusters
        ranked = sorted(
            tool_scores.keys(),
            key=lambda t: sum(tool_scores[t]) / len(tool_scores[t]),
            reverse=True,
        )
        winner_id = ranked[0]
        winner_tool = self._get_tool(winner_id)
        winner_mean = sum(tool_scores[winner_id]) / len(tool_scores[winner_id])

        # Most common algorithm for winner
        algo_list = [a for a in tool_algorithms[winner_id] if a]
        best_algo = max(set(algo_list), key=algo_list.count) if algo_list else "Unknown"

        # Pass count estimate
        pass_count = self.estimate_pass_count(
            [a["entropy"] for a in region_analyses]
        )

        runner_up = None
        if len(ranked) > 1:
            ru_id = ranked[1]
            ru_tool = self._get_tool(ru_id)
            runner_up = ru_tool["name"] if ru_tool else ru_id

        return {
            "tool": winner_tool["name"] if winner_tool else winner_id,
            "tool_id": winner_id,
            "algorithm": best_algo,
            "pass_count": pass_count,
            "confidence": round(winner_mean, 4),
            "evidence": list(evidence_set)[:6],
            "runner_up": runner_up,
        }

    def estimate_pass_count(self, entropy_series: list[float]) -> int:
        """
        Heuristically estimate number of overwrite passes from entropy data.

        Single-pass zero fill → entropy ~0.0, very consistent  → 1
        Multi-pass random    → entropy ~8.0, very consistent  → 3+
        Mixed/alternating    → entropy varies                 → 2+
        """
        if not entropy_series:
            return 0

        # Subsample for performance
        MAX_SAMPLES = 1000
        if len(entropy_series) > MAX_SAMPLES:
            step = len(entropy_series) // MAX_SAMPLES
            data = entropy_series[::step][:MAX_SAMPLES]
        else:
            data = entropy_series

        mean_e = sum(data) / len(data)
        variance = sum((e - mean_e) ** 2 for e in data) / len(data)

        if mean_e < 0.1 and variance < 0.01:
            return 1  # Pure zero fill
        if mean_e > 7.9 and variance < 0.05:
            return 1  # Pure random fill (single pass)
        if mean_e > 7.5 and variance < 0.1:
            return 3  # Likely multi-pass (final pass was random)
        if variance > 5.0:
            return 2  # High entropy variance → clearly alternating pass types
        if mean_e > 5.0 and variance > 0.5:
            return 2  # Two distinct pass types
        if mean_e > 7.0:
            return 3
        return 1

    def detect_incomplete_wipe(self, cluster_analyses: list[dict]) -> dict:
        """
        Identify clusters that were NOT fully wiped within an otherwise-wiped region.

        Returns:
        {
            "has_incomplete_wipe": bool,
            "intact_cluster_count": int,
            "intact_fraction":      float,
            "intact_cluster_ids":   list[int],   # indices in the input list
            "risk_note":            str
        }
        """
        intact_ids = []
        for i, analysis in enumerate(cluster_analyses):
            cls = analysis.get("classification", "")
            if cls in ("natural_residual", "os_clear"):
                intact_ids.append(i)

        total = len(cluster_analyses)
        intact_count = len(intact_ids)
        intact_fraction = intact_count / total if total else 0.0

        note = ""
        if intact_fraction > 0.3:
            note = "More than 30% of region is intact — incomplete or interrupted wipe"
        elif intact_fraction > 0.05:
            note = "Small number of intact clusters — possible tool failure or partial coverage"
        elif intact_fraction > 0.0:
            note = "Isolated intact clusters — wipe was nearly complete; remnants may exist"
        else:
            note = "No intact clusters detected — region appears fully wiped"

        return {
            "has_incomplete_wipe": intact_count > 0,
            "intact_cluster_count": intact_count,
            "intact_fraction": round(intact_fraction, 4),
            "intact_cluster_ids": intact_ids[:50],  # cap output
            "risk_note": note,
        }

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    def _get_tool(self, tool_id: str) -> dict | None:
        for t in self._profiles:
            if t["id"] == tool_id:
                return t
        return None

    def _unknown_result(self, reason: str) -> dict:
        return {
            "tool": "Unknown",
            "tool_id": "unknown",
            "algorithm": "Unknown",
            "pass_count": 0,
            "confidence": 0.0,
            "evidence": [reason],
            "runner_up": None,
        }

    def list_tools(self) -> list[str]:
        return [t["name"] for t in self._profiles]
