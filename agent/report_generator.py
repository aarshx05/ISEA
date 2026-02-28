"""
Forensic Report Generator

Produces structured JSON and human-readable Markdown reports
from a completed ScanResult. Reports are designed to be
admissible-quality documentation for legal proceedings.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

from core.cluster_scanner import ScanResult


class ReportGenerator:
    """
    Generates forensic reports from a ScanResult.

    Sections:
      1. Executive Summary
      2. Technical Findings
      3. Wipe Tool Classification
      4. Intent Assessment
      5. Evidence Scoring
      6. Recommended Actions
    """

    VERSION = "1.0.0"

    def __init__(self, scan_result: ScanResult):
        self._r = scan_result
        self._generated_at = datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def evidence_strength_rating(self) -> str:
        score = self._r.evidence_score
        if score >= 75:
            return "STRONG"
        if score >= 50:
            return "PROBABLE"
        if score >= 25:
            return "POSSIBLE"
        return "INSUFFICIENT"

    def to_json(self) -> str:
        """Return the full structured evidence report as a JSON string."""
        report = {
            "report_metadata": {
                "tool": "ISEA — Intelligent Storage Evidence Analyzer",
                "version": self.VERSION,
                "generated_at": self._generated_at,
            },
            "image_info": {
                "path": self._r.image_path,
                "size_bytes": self._r.image_size_bytes,
                "size_mb": round(self._r.image_size_bytes / (1024 * 1024), 2),
                "cluster_size": self._r.cluster_size,
                "total_clusters": self._r.total_clusters,
                "analyzed_clusters": self._r.analyzed_clusters,
                "scan_duration_seconds": self._r.scan_duration_seconds,
                "scan_step": self._r.scan_step,
            },
            "executive_summary": self._build_executive_summary(),
            "technical_findings": self._build_technical_findings(),
            "wipe_tool_classification": self._build_tool_classification(),
            "intent_assessment": self._r.intent_assessment,
            "evidence_scoring": self._build_evidence_scoring(),
            "wipe_detections": [w.to_dict() for w in self._r.wipe_detections],
            "recommended_actions": self._build_recommended_actions(),
        }
        return json.dumps(report, indent=2, default=str)

    def to_markdown(self) -> str:
        """Return a human-readable forensic report in Markdown format."""
        lines = []
        r = self._r
        strength = self.evidence_strength_rating()
        intent = r.intent_assessment

        # Header
        lines += [
            "# ISEA Forensic Analysis Report",
            f"**Generated:** {self._generated_at}  ",
            f"**ISEA Version:** {self.VERSION}  ",
            "",
            "---",
            "",
        ]

        # Executive Summary
        lines += [
            "## Executive Summary",
            "",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| Image | `{Path(r.image_path).name}` |",
            f"| Size | {round(r.image_size_bytes / (1024*1024), 2)} MB |",
            f"| Total Clusters | {r.total_clusters:,} |",
            f"| Wipe Regions Detected | {len(r.wipe_detections)} |",
            f"| Evidence Score | **{r.evidence_score}/100** |",
            f"| Evidence Strength | **{strength}** |",
            f"| Risk Level | **{intent.get('risk_level', 'UNKNOWN')}** |",
            f"| Scan Duration | {r.scan_duration_seconds:.1f}s |",
            "",
        ]

        # Intent hypothesis
        hypothesis = intent.get("hypothesis", "N/A")
        lines += [
            "### Analyst Hypothesis",
            "",
            f"> {hypothesis}",
            "",
        ]

        # Technical Findings
        stats = r.region_stats
        lines += [
            "---",
            "",
            "## Technical Findings",
            "",
            "### Cluster Classification Breakdown",
            "",
        ]
        by_class = stats.get("by_classification", {})
        total_analyzed = r.analyzed_clusters or 1
        for cls, count in sorted(by_class.items(), key=lambda x: -x[1]):
            pct = count / total_analyzed * 100
            bar = "█" * int(pct / 5)
            lines.append(f"- **{cls}**: {count:,} clusters ({pct:.1f}%) {bar}")
        lines += [
            "",
            f"- **Mean Entropy:** {stats.get('mean_entropy', 0.0):.4f} bits/byte",
            f"- **Wipe Fraction:** {stats.get('wipe_fraction', 0.0):.1%}",
            "",
        ]

        # Wipe Tool Classification
        lines += [
            "---",
            "",
            "## Wipe Tool Classification",
            "",
        ]
        if r.signature_matches:
            sig = r.signature_matches[0]
            lines += [
                f"| Field | Value |",
                f"|-------|-------|",
                f"| Most Likely Tool | **{sig.get('tool', 'Unknown')}** |",
                f"| Algorithm | {sig.get('algorithm', 'Unknown')} |",
                f"| Est. Pass Count | {sig.get('pass_count', 0)} |",
                f"| Confidence | {sig.get('confidence', 0):.1%} |",
                f"| Runner-Up | {sig.get('runner_up') or 'None'} |",
                "",
            ]
            evidence_items = sig.get("evidence", [])
            if evidence_items:
                lines.append("**Signature Evidence:**")
                for item in evidence_items:
                    lines.append(f"- {item}")
                lines.append("")

            # Incomplete wipe
            incomplete = sig.get("incomplete_wipe", {})
            if incomplete.get("has_incomplete_wipe"):
                lines += [
                    "### Incomplete Wipe Analysis",
                    "",
                    f"> {incomplete.get('risk_note', '')}",
                    f"- Intact clusters: {incomplete.get('intact_cluster_count', 0)}",
                    f"- Intact fraction: {incomplete.get('intact_fraction', 0):.1%}",
                    "",
                ]
        else:
            lines += ["*No significant wipe tool signatures detected.*", ""]

        # Wipe Detections
        if r.wipe_detections:
            lines += [
                "---",
                "",
                "## Wipe Region Detections",
                "",
                f"**{len(r.wipe_detections)} wipe region(s) identified.**",
                "",
                "| # | Clusters | Tool | Algorithm | Passes | Confidence | Entropy |",
                "|---|----------|------|-----------|--------|------------|---------|",
            ]
            for i, w in enumerate(r.wipe_detections[:25], 1):
                lines.append(
                    f"| {i} | {w.start_cluster}–{w.end_cluster} "
                    f"({w.cluster_count}) | {w.tool_match} | {w.algorithm} "
                    f"| {w.pass_count} | {w.confidence:.0%} | {w.mean_entropy:.2f} |"
                )
            if len(r.wipe_detections) > 25:
                lines.append(f"| ... | *{len(r.wipe_detections) - 25} more regions* | | | | | |")
            lines.append("")

        # Intent Assessment
        lines += [
            "---",
            "",
            "## Behavioral Intent Assessment",
            "",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| Intent Score | **{intent.get('score', 0):.1f}/100** |",
            f"| Confidence Tier | **{intent.get('confidence', 'LOW')}** |",
            f"| Wipe Scope | {intent.get('wipe_scope', 'unknown')} |",
            f"| Temporal Correlation | {intent.get('temporal_correlation', False)} |",
            f"| Sensitive Dir Targeted | {intent.get('sensitive_dir_targeted', False)} |",
            "",
        ]
        evidence_pts = intent.get("evidence_points", [])
        if evidence_pts:
            lines.append("**Behavioral Evidence Points:**")
            for pt in evidence_pts:
                lines.append(f"- {pt}")
            lines.append("")
        targeted_dirs = intent.get("targeted_dirs", [])
        if targeted_dirs:
            lines.append("**Targeted Directories:**")
            for d in targeted_dirs:
                lines.append(f"- `{d}`")
            lines.append("")

        # Evidence Scoring
        lines += [
            "---",
            "",
            "## Evidence Scoring",
            "",
            f"**Overall Evidence Score: {r.evidence_score}/100**  ",
            f"**Evidence Strength Rating: {strength}**",
            "",
            "| Component | Weight | Contribution |",
            "|-----------|--------|-------------|",
            f"| Behavioral Intent Score | 40% | {intent.get('score', 0) * 0.4:.1f}/40 |",
            f"| Wipe Fraction | 30% | {stats.get('wipe_fraction', 0) * 100 * 0.3:.1f}/30 |",
            f"| Signature Match Confidence | 20% | — |",
            f"| Region Count Factor | 10% | {min(len(r.wipe_detections)/10, 1)*10:.1f}/10 |",
            "",
        ]

        # Recommended Actions
        lines += [
            "---",
            "",
            "## Recommended Actions",
            "",
        ]
        for action in self._build_recommended_actions():
            lines.append(f"- {action}")

        lines += [
            "",
            "---",
            "",
            "*This report was generated by ISEA — Intelligent Storage Evidence Analyzer.*  ",
            "*All findings are based on statistical and behavioral analysis.*  ",
            "*Consult a certified digital forensics expert for legal proceedings.*",
        ]

        return "\n".join(lines)

    # ------------------------------------------------------------------ #
    # Internal section builders
    # ------------------------------------------------------------------ #

    def _build_executive_summary(self) -> dict:
        intent = self._r.intent_assessment
        return {
            "evidence_strength": self.evidence_strength_rating(),
            "risk_level": intent.get("risk_level", "MINIMAL"),
            "evidence_score": self._r.evidence_score,
            "wipe_regions_detected": len(self._r.wipe_detections),
            "wipe_fraction": self._r.region_stats.get("wipe_fraction", 0.0),
            "hypothesis": intent.get("hypothesis", ""),
            "intent_confidence": intent.get("confidence", "LOW"),
        }

    def _build_technical_findings(self) -> dict:
        return {
            "region_statistics": self._r.region_stats,
            "cluster_analysis_sample": self._r.cluster_analyses[:5],
        }

    def _build_tool_classification(self) -> dict:
        if self._r.signature_matches:
            return self._r.signature_matches[0]
        return {"status": "no_significant_wipe_detected"}

    def _build_evidence_scoring(self) -> dict:
        intent = self._r.intent_assessment
        stats = self._r.region_stats
        return {
            "overall_score": self._r.evidence_score,
            "evidence_strength": self.evidence_strength_rating(),
            "components": {
                "intent_score": {"weight": 0.40, "raw": intent.get("score", 0)},
                "wipe_fraction": {"weight": 0.30, "raw": stats.get("wipe_fraction", 0) * 100},
                "mean_confidence": {"weight": 0.20, "raw": stats.get("mean_confidence", 0) * 100},
                "region_count": {
                    "weight": 0.10,
                    "raw": min(len(self._r.wipe_detections) / 10.0, 1.0) * 100,
                },
            },
        }

    def _build_recommended_actions(self) -> list[str]:
        score = self._r.evidence_score
        intent = self._r.intent_assessment
        actions = []

        if score >= 75:
            actions += [
                "Secure the original disk image immediately — maintain strict chain of custody",
                "Create verified forensic copies (MD5/SHA256 hash validation required)",
                "Engage a certified digital forensics examiner (CFCE/EnCE/GCFE)",
                "Correlate findings with system event logs, access logs, and user activity",
                "Preserve all related systems and backup media as potential evidence",
                "Document all analysis steps for courtroom admissibility",
            ]
        elif score >= 50:
            actions += [
                "Preserve the disk image with hash verification",
                "Cross-reference wipe timestamps with user session data",
                "Examine network logs for data exfiltration prior to wipe",
                "Consult a forensics professional for deeper analysis",
            ]
        elif score >= 25:
            actions += [
                "Retain disk image for potential future analysis",
                "Review system maintenance logs to rule out legitimate clearing",
                "Monitor for related suspicious activity on other systems",
            ]
        else:
            actions += [
                "Activity appears consistent with normal OS behavior",
                "No immediate forensic action required",
                "Document findings for completeness",
            ]

        if intent.get("sensitive_dir_targeted"):
            actions.append(
                "Sensitive directories were targeted — assess scope of data loss and notify relevant stakeholders"
            )

        if intent.get("wipe_scope") == "full_disk":
            actions.append(
                "Full-disk wipe detected — consider live memory forensics if system is still running"
            )

        return actions
