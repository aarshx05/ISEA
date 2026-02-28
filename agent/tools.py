"""
Agent Tool Definitions and Executor

Defines the Groq function-calling tool schemas and the ToolExecutor class
that routes agent tool calls to actual scan result data.
"""

import json
from pathlib import Path

from core.cluster_scanner import ClusterScanner, ScanResult


# ------------------------------------------------------------------ #
# Tool schema definitions (Groq function-calling format)
# ------------------------------------------------------------------ #

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "get_scan_summary",
            "description": (
                "Get a high-level summary of the disk scan: image size, total clusters, "
                "wipe regions found, top tools detected, evidence score, risk level, "
                "and classification breakdown. Always call this first."
            ),
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "analyze_disk_region",
            "description": (
                "Analyze entropy and wipe patterns for a specific cluster range. "
                "Returns per-cluster classification data including entropy values, "
                "fill patterns, and wipe likelihood. Use to drill into suspicious areas."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "cluster_start": {
                        "type": "integer",
                        "description": "First cluster index to analyze (0-based)",
                    },
                    "cluster_end": {
                        "type": "integer",
                        "description": "Last cluster index to analyze (exclusive)",
                    },
                },
                "required": ["cluster_start", "cluster_end"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_wipe_detections",
            "description": (
                "List all detected wipe regions with their tool classification, algorithm, "
                "pass count, confidence score, and cluster range. "
                "Returns each region as a structured dict."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "min_confidence": {
                        "type": "number",
                        "description": "Filter to regions above this confidence threshold (0.0–1.0). Default 0.0.",
                    }
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_wipe_signature_match",
            "description": (
                "Get the full wipe tool classification for the entire image: "
                "most likely tool, algorithm, estimated pass count, confidence, and evidence list. "
                "Also returns incomplete wipe analysis."
            ),
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_intent_assessment",
            "description": (
                "Get the behavioral intent analysis: intent score (0–100), hypothesis text, "
                "confidence tier, risk level, wipe scope (selective/partition/full_disk), "
                "targeted directories, and temporal correlation with deletions. "
                "Use when the user asks about attacker intent, deliberateness, or purpose."
            ),
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_directory_analysis",
            "description": (
                "Get wipe analysis information for a specific directory path or keyword. "
                "Shows whether that directory was targeted by wiping activity."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "directory_path": {
                        "type": "string",
                        "description": "Directory path or keyword to search (e.g. 'finance', '/documents')",
                    }
                },
                "required": ["directory_path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_evidence_score_breakdown",
            "description": (
                "Get the detailed evidence score breakdown: overall score (0–100), "
                "contributing factors, evidence strength rating, and recommended actions."
            ),
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "generate_evidence_report",
            "description": (
                "Generate and save a full forensic report (JSON + Markdown). "
                "Returns the report file paths. Use when the user asks for a full report."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "output_dir": {
                        "type": "string",
                        "description": "Directory to save report files. Defaults to ./reports",
                    }
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "detect_hidden_encrypted_volumes",
            "description": (
                "Return analysis of high-entropy unallocated regions suspected to contain "
                "hidden encrypted volumes (VeraCrypt, TrueCrypt, BitLocker). "
                "Uses chi-square byte uniformity testing, entropy boundary sharpness analysis, "
                "and outer filesystem detection to distinguish encryption from random-fill wipe tools. "
                "Use this when investigating plausible deniability, data concealment, or when "
                "high-entropy regions exist but no wipe tool was clearly identified."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "min_confidence": {
                        "type": "number",
                        "description": (
                            "Minimum confidence threshold 0.0–1.0 for returned candidates. "
                            "Default 0.4. Use 0.6 for high-confidence results only."
                        ),
                    }
                },
                "required": [],
            },
        },
    },
]


# ------------------------------------------------------------------ #
# Tool executor
# ------------------------------------------------------------------ #

class ToolExecutor:
    """
    Routes agent tool calls to actual ScanResult data.
    All methods return JSON-serializable dicts.
    """

    def __init__(self, scan_result: ScanResult, scanner: ClusterScanner):
        self._result = scan_result
        self._scanner = scanner

    def execute(self, tool_name: str, arguments: dict) -> dict:
        """Dispatch tool call to the appropriate handler."""
        handlers = {
            "get_scan_summary":                  self._get_scan_summary,
            "analyze_disk_region":               self._analyze_disk_region,
            "get_wipe_detections":               self._get_wipe_detections,
            "get_wipe_signature_match":          self._get_wipe_signature_match,
            "get_intent_assessment":             self._get_intent_assessment,
            "get_directory_analysis":            self._get_directory_analysis,
            "get_evidence_score_breakdown":      self._get_evidence_score_breakdown,
            "generate_evidence_report":          self._generate_evidence_report,
            "detect_hidden_encrypted_volumes":   self._detect_hidden_encrypted_volumes,
        }
        handler = handlers.get(tool_name)
        if not handler:
            return {"error": f"Unknown tool: {tool_name}"}
        try:
            return handler(**arguments)
        except Exception as exc:
            return {"error": str(exc), "tool": tool_name}

    def _get_scan_summary(self) -> dict:
        return self._scanner.get_summary(self._result)

    def _analyze_disk_region(self, cluster_start: int, cluster_end: int) -> dict:
        analyses = self._scanner.scan_region(cluster_start, cluster_end)
        # Summarize — don't return raw per-cluster data (too large)
        from core.entropy_engine import EntropyEngine
        engine = EntropyEngine()
        stats = engine.aggregate_region_stats(analyses)
        return {
            "cluster_range": f"{cluster_start}–{cluster_end}",
            "clusters_analyzed": len(analyses),
            "stats": stats,
            "sample_classifications": [
                {"cluster_id": a.get("cluster_id"), "classification": a["classification"],
                 "entropy": a["entropy"], "confidence": a["confidence"]}
                for a in analyses[:10]  # first 10 as sample
            ],
        }

    def _get_wipe_detections(self, min_confidence: float = 0.0) -> dict:
        filtered = [
            w.to_dict() for w in self._result.wipe_detections
            if w.confidence >= min_confidence
        ]
        return {
            "total_wipe_regions": len(self._result.wipe_detections),
            "filtered_count": len(filtered),
            "detections": filtered[:20],  # cap at 20 for readability
        }

    def _get_wipe_signature_match(self) -> dict:
        if self._result.signature_matches:
            return self._result.signature_matches[0]
        return {"message": "No significant wipe signatures detected in this image."}

    def _get_intent_assessment(self) -> dict:
        return self._result.intent_assessment

    def _get_directory_analysis(self, directory_path: str) -> dict:
        keyword = directory_path.lower().strip("/")
        targeted = self._result.intent_assessment.get("targeted_dirs", [])
        matching = [d for d in targeted if keyword in d.lower()]
        wipe_regions_in_dir = []
        for w in self._result.wipe_detections:
            hint = (w.directory_hint or "").lower()
            if keyword in hint:
                wipe_regions_in_dir.append(w.to_dict())
        return {
            "query": directory_path,
            "directory_targeted": bool(matching or wipe_regions_in_dir),
            "matching_dirs": matching,
            "wipe_regions": wipe_regions_in_dir,
            "note": (
                f"Directory '{directory_path}' appears in wipe analysis."
                if (matching or wipe_regions_in_dir)
                else f"No specific targeting of '{directory_path}' detected."
            ),
        }

    def _get_evidence_score_breakdown(self) -> dict:
        score = self._result.evidence_score
        intent = self._result.intent_assessment
        risk = intent.get("risk_level", "MINIMAL")

        if score >= 75:
            strength = "STRONG"
            recommendation = (
                "Evidence strongly supports intentional data destruction. "
                "Recommend chain-of-custody documentation, bit-for-bit imaging, "
                "and expert witness consultation for legal proceedings."
            )
        elif score >= 50:
            strength = "PROBABLE"
            recommendation = (
                "Evidence is probable but not conclusive. "
                "Recommend deeper filesystem analysis and correlation with user activity logs."
            )
        elif score >= 25:
            strength = "POSSIBLE"
            recommendation = (
                "Some indicators of intentional wiping. "
                "Could be routine maintenance — further investigation warranted."
            )
        else:
            strength = "INSUFFICIENT"
            recommendation = "Insufficient evidence to conclude intentional data destruction."

        return {
            "overall_score": score,
            "evidence_strength": strength,
            "risk_level": risk,
            "contributing_factors": {
                "behavioral_intent": f"{intent.get('score', 0):.1f}/100",
                "wipe_fraction": f"{self._result.region_stats.get('wipe_fraction', 0):.1%}",
                "wipe_regions_found": len(self._result.wipe_detections),
                "mean_confidence": self._result.region_stats.get("mean_confidence", 0),
            },
            "recommendation": recommendation,
            "evidence_points": intent.get("evidence_points", []),
        }

    def _generate_evidence_report(self, output_dir: str = "./reports") -> dict:
        from agent.report_generator import ReportGenerator
        import os

        os.makedirs(output_dir, exist_ok=True)
        generator = ReportGenerator(self._result)

        # Write JSON report
        json_path = Path(output_dir) / "isea_report.json"
        json_path.write_text(generator.to_json(), encoding="utf-8")

        # Write Markdown report
        md_path = Path(output_dir) / "isea_report.md"
        md_path.write_text(generator.to_markdown(), encoding="utf-8")

        return {
            "status": "success",
            "json_report": str(json_path.resolve()),
            "markdown_report": str(md_path.resolve()),
            "evidence_strength": generator.evidence_strength_rating(),
        }

    def _detect_hidden_encrypted_volumes(self, min_confidence: float = 0.4) -> dict:
        """
        Return hidden encrypted volume candidates from the scan result,
        filtered by minimum confidence threshold.
        """
        hvs = self._result.hidden_volume_detections or []

        filtered = []
        for h in hvs:
            conf = h.confidence if hasattr(h, "confidence") else h.get("confidence", 0.0)
            if conf >= min_confidence:
                filtered.append(h.to_dict() if hasattr(h, "to_dict") else h)

        all_confs = [
            (h.confidence if hasattr(h, "confidence") else h.get("confidence", 0.0))
            for h in hvs
        ]
        highest = max(all_confs, default=0.0)
        plausible_deniability_risk = any(c >= 0.7 for c in all_confs)

        if not filtered:
            return {
                "count": 0,
                "candidates": [],
                "highest_confidence": round(highest, 4),
                "plausible_deniability_risk": plausible_deniability_risk,
                "summary": "No hidden encrypted volume candidates detected above the confidence threshold.",
            }

        # Build a human-readable summary
        tool_hints = list({
            (h.get("tool_hint", "Unknown") if isinstance(h, dict) else h.get("tool_hint", "Unknown"))
            for h in filtered
        })
        summary = (
            f"Detected {len(filtered)} hidden encrypted volume candidate(s). "
            f"Suspected tool(s): {', '.join(tool_hints)}. "
            f"Highest confidence: {highest * 100:.1f}%. "
        )
        if plausible_deniability_risk:
            summary += (
                "PLAUSIBLE DENIABILITY RISK DETECTED — a VeraCrypt-style outer volume "
                "may be concealing encrypted data from investigators."
            )

        return {
            "count": len(filtered),
            "candidates": filtered,
            "highest_confidence": round(highest, 4),
            "plausible_deniability_risk": plausible_deniability_risk,
            "summary": summary,
        }
