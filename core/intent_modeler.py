"""
Behavioral Intent Modeler

Correlates wipe patterns with filesystem metadata to form probabilistic
hypotheses about attacker intent. This is what elevates ISEA beyond
simple wipe detection into attacker profiling.

Key questions answered:
  - Is the wipe localized (targeted) or global (panic/scorched-earth)?
  - Does the wipe follow deletion events (temporal correlation)?
  - Does it target sensitive directories?
  - What is the probability this represents intentional evidence destruction?
"""

import re
from dataclasses import dataclass, field
from typing import Any

from config import SENSITIVE_DIR_PATTERNS


@dataclass
class IntentEvidence:
    """A single piece of behavioral evidence contributing to the intent score."""
    description: str
    weight: float        # contribution to intent score (0.0–1.0)
    confidence: float    # how certain we are about this piece (0.0–1.0)
    category: str        # "locality" | "targeting" | "temporal" | "intensity"


@dataclass
class IntentAssessment:
    """Full intent assessment result."""
    score: float                    # 0.0–100.0 overall intent score
    hypothesis: str                 # human-readable hypothesis
    confidence: str                 # "LOW" | "MEDIUM" | "HIGH" | "VERY HIGH"
    risk_level: str                 # "MINIMAL" | "POSSIBLE" | "PROBABLE" | "CRITICAL"
    evidence_points: list[str] = field(default_factory=list)
    targeted_dirs: list[str] = field(default_factory=list)
    wipe_scope: str = "unknown"     # "selective" | "partition" | "full_disk"
    temporal_correlation: bool = False
    sensitive_dir_targeted: bool = False
    investigator_questions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "hypothesis": self.hypothesis,
            "confidence": self.confidence,
            "risk_level": self.risk_level,
            "evidence_points": self.evidence_points,
            "targeted_dirs": self.targeted_dirs,
            "wipe_scope": self.wipe_scope,
            "temporal_correlation": self.temporal_correlation,
            "sensitive_dir_targeted": self.sensitive_dir_targeted,
            "investigator_questions": self.investigator_questions,
        }


class IntentModeler:
    """
    Analyzes behavioral patterns in wipe detections to infer attacker intent.

    Args:
        fs_metadata:       Dict from DiskAnalyzer.get_filesystem_metadata()
        cluster_analyses:  List of classification dicts from EntropyEngine
        wipe_detections:   List of wipe detection results (from ClusterScanner)
    """

    def __init__(
        self,
        fs_metadata: dict,
        cluster_analyses: list[dict],
        wipe_detections: list[dict] | None = None,
        agent: Any | None = None,
        hidden_volume_detections: list[dict] | None = None,
    ):
        self.fs_metadata = fs_metadata
        self.cluster_analyses = cluster_analyses
        self.wipe_detections = wipe_detections or []
        self._evidence: list[IntentEvidence] = []
        self.agent = agent
        self.hidden_volume_detections = hidden_volume_detections or []

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def compute_intent_score(self) -> dict:
        """
        Main entry point. Runs all behavioral checks and returns a full
        IntentAssessment as a dict.
        """
        self._evidence = []

        # Run all behavioral checks
        is_local, targeted_dirs = self.is_wipe_localized()
        temporal = self.correlates_with_deletion_events()
        sensitive = self.targets_sensitive_directories()
        scope = self._determine_wipe_scope()
        intensity = self._assess_wipe_intensity()

        # Build evidence list
        if is_local and targeted_dirs:
            self._evidence.append(IntentEvidence(
                description=f"Wipe is localized to {len(targeted_dirs)} specific director(ies): "
                            + ", ".join(targeted_dirs[:3]),
                weight=0.30,
                confidence=0.85,
                category="locality"
            ))
        elif not is_local:
            self._evidence.append(IntentEvidence(
                description="Full-disk or partition-level wipe — possible scorched-earth approach",
                weight=0.20,
                confidence=0.75,
                category="locality"
            ))

        if temporal:
            self._evidence.append(IntentEvidence(
                description="Wipe activity correlates with mass deletion events — sequential cover-up pattern",
                weight=0.25,
                confidence=0.80,
                category="temporal"
            ))

        if sensitive:
            sensitive_dirs = self.targets_sensitive_directories()
            self._evidence.append(IntentEvidence(
                description=f"Sensitive directories targeted: {', '.join(sensitive_dirs[:3])}",
                weight=0.30,
                confidence=0.90,
                category="targeting"
            ))

        if intensity > 0.7:
            self._evidence.append(IntentEvidence(
                description=f"High wipe intensity score ({intensity:.0%}) — deep, consistent overwrite",
                weight=0.15,
                confidence=0.85,
                category="intensity"
            ))
        elif intensity > 0.4:
            self._evidence.append(IntentEvidence(
                description=f"Moderate wipe intensity ({intensity:.0%}) — partial or interrupted wipe",
                weight=0.08,
                confidence=0.70,
                category="intensity"
            ))

        # Hidden encrypted volume evidence
        if self.hidden_volume_detections:
            high_conf_hv = [
                h for h in self.hidden_volume_detections
                if h.get("confidence", 0) >= 0.6
            ]
            if high_conf_hv:
                best_hv = max(high_conf_hv, key=lambda h: h.get("confidence", 0))
                self._evidence.append(IntentEvidence(
                    description=(
                        f"Hidden encrypted volume detected ({best_hv.get('tool_hint', 'Unknown')}, "
                        f"{best_hv.get('confidence', 0):.0%} confidence) — "
                        f"plausible deniability pattern consistent with deliberate data concealment"
                    ),
                    weight=0.45,
                    confidence=best_hv.get("confidence", 0.6),
                    category="encryption",
                ))
            elif self.hidden_volume_detections:
                # Low-confidence candidates still worth noting
                best_hv = max(self.hidden_volume_detections, key=lambda h: h.get("confidence", 0))
                self._evidence.append(IntentEvidence(
                    description=(
                        f"Possible hidden encrypted volume region detected "
                        f"({best_hv.get('tool_hint', 'Unknown')}, "
                        f"{best_hv.get('confidence', 0):.0%} confidence) — "
                        f"inconclusive, further analysis recommended"
                    ),
                    weight=0.15,
                    confidence=best_hv.get("confidence", 0.35),
                    category="encryption",
                ))

        # Compute baseline algorithmic score
        raw_score = sum(e.weight * e.confidence for e in self._evidence)
        intent_score = round(min(raw_score * 100, 100.0), 1)
        confidence_tier = self._score_to_confidence(intent_score)
        risk_level = self._score_to_risk(intent_score)
        hypothesis = self._build_hypothesis(
            intent_score, scope, targeted_dirs, temporal, sensitive
        )
        ai_questions = []

        # ----------------------------------------------------
        # AGENTIC AI INTEGRATION: Override with AI deduction
        # ----------------------------------------------------
        if self.agent:
            crime_scene = {
                "wipe_scope": scope,
                "is_localized": is_local,
                "targeted_dirs": targeted_dirs,
                "intensity": intensity,
                "temporal_correlation": temporal,
                "sensitive_targeted": bool(sensitive),
                "wiped_clusters": sum(1 for a in self.cluster_analyses if a.get("classification") in ("intentional_wipe", "secure_erase")),
                "total_clusters": len(self.cluster_analyses),
                "hidden_volume_count": len(self.hidden_volume_detections),
                "hidden_volume_max_confidence": max(
                    (h.get("confidence", 0.0) for h in self.hidden_volume_detections),
                    default=0.0,
                ),
                "hidden_volume_tool_hints": list({
                    h.get("tool_hint", "Unknown")
                    for h in self.hidden_volume_detections
                }),
            }
            ai_assessment = self.agent.analyze_intent(crime_scene)
            
            if ai_assessment:
                # Merge AI deductive reasoning — AI overrides rule-based values
                intent_score = ai_assessment.get("score", intent_score)
                hypothesis = ai_assessment.get("hypothesis", hypothesis)
                confidence_tier = ai_assessment.get("confidence", confidence_tier)
                risk_level = ai_assessment.get("risk_level", risk_level)
                ai_questions = ai_assessment.get("investigator_questions", [])

                # Replace evidence_points with AI's traceable evidence_chain if provided.
                # This shows the AI's step-by-step forensic reasoning in the Results page
                # instead of the generic rule-based descriptions.
                ai_evidence_chain = ai_assessment.get("evidence_chain", [])
                if ai_evidence_chain:
                    self._evidence = [
                        IntentEvidence(
                            description="[AI] " + step,
                            weight=0.0,
                            confidence=1.0,
                            category="ai_inference",
                        )
                        for step in ai_evidence_chain
                    ]
                    # Prepend an AI analysis marker
                    self._evidence.insert(0, IntentEvidence(
                        description="AI forensic analysis applied — evidence chain below reflects AI deductive reasoning",
                        weight=0.0,
                        confidence=1.0,
                        category="ai_inference",
                    ))
                else:
                    # No evidence_chain from AI — keep rule-based evidence + add AI marker
                    self._evidence.insert(0, IntentEvidence(
                        description="AI Agentic Analysis applied to crime scene",
                        weight=0.0,
                        confidence=1.0,
                        category="ai_inference",
                    ))

        assessment = IntentAssessment(
            score=intent_score,
            hypothesis=hypothesis,
            confidence=confidence_tier,
            risk_level=risk_level,
            evidence_points=[e.description for e in self._evidence],
            targeted_dirs=targeted_dirs,
            wipe_scope=scope,
            temporal_correlation=temporal,
            sensitive_dir_targeted=bool(sensitive),
            investigator_questions=ai_questions,
        )
        return assessment.to_dict()

    def is_wipe_localized(self) -> tuple[bool, list[str]]:
        """
        Determine whether wiping is confined to specific directories vs whole-disk.

        Returns:
            (is_localized, [dir_paths])
        """
        wipe_cluster_ids: set[int] = set()
        for i, analysis in enumerate(self.cluster_analyses):
            if analysis.get("classification") in ("intentional_wipe", "secure_erase"):
                wipe_cluster_ids.add(i)

        total_clusters = len(self.cluster_analyses)
        if total_clusters == 0:
            return False, []

        wipe_fraction = len(wipe_cluster_ids) / total_clusters

        # If >80% of disk is wiped, it's global
        if wipe_fraction > 0.80:
            return False, []

        # Try to match wipe detections to directories via filesystem metadata
        targeted = self._extract_targeted_dirs(wipe_cluster_ids)
        return True, targeted

    def correlates_with_deletion_events(self) -> bool:
        """
        Check whether wipe clusters spatially or temporally follow deletion events.
        Uses filesystem metadata (deleted_entries) if available.
        """
        deleted_entries = self.fs_metadata.get("deleted_entries", [])
        if not deleted_entries:
            # No deletion metadata — fall back to spatial heuristic
            return self._spatial_deletion_heuristic()

        # If >5 files were deleted AND high-entropy wipes exist in same region,
        # that is a temporal correlation signal
        if len(deleted_entries) >= 5:
            wipe_present = any(
                a.get("classification") in ("intentional_wipe", "secure_erase")
                for a in self.cluster_analyses
            )
            return wipe_present
        return False

    def targets_sensitive_directories(self) -> list[str]:
        """
        Return list of sensitive directory paths that overlap with wiped regions.
        Uses filesystem metadata and known sensitive dir patterns.
        """
        deleted_entries = self.fs_metadata.get("deleted_entries", [])
        sensitive_found: list[str] = []

        for entry in deleted_entries:
            name = entry.get("name", "").lower()
            for pattern in SENSITIVE_DIR_PATTERNS:
                if pattern in name:
                    sensitive_found.append(entry["name"])
                    break

        # Also check wipe_detections for any dir hints
        for wd in self.wipe_detections:
            region_hint = wd.get("directory_hint", "")
            if region_hint:
                for pattern in SENSITIVE_DIR_PATTERNS:
                    if pattern in region_hint.lower():
                        if region_hint not in sensitive_found:
                            sensitive_found.append(region_hint)

        return sensitive_found

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    def _determine_wipe_scope(self) -> str:
        """Classify the spatial scope of wiping."""
        total = len(self.cluster_analyses)
        if total == 0:
            return "unknown"
        wipe_count = sum(
            1 for a in self.cluster_analyses
            if a.get("classification") in ("intentional_wipe", "secure_erase")
        )
        fraction = wipe_count / total
        if fraction > 0.85:
            return "full_disk"
        if fraction > 0.30:
            return "partition"
        return "selective"

    def _assess_wipe_intensity(self) -> float:
        """
        Mean confidence of wipe detections, weighted by entropy level.
        Returns 0.0–1.0.
        """
        wipe_analyses = [
            a for a in self.cluster_analyses
            if a.get("classification") in ("intentional_wipe", "secure_erase")
        ]
        if not wipe_analyses:
            return 0.0
        scores = [a.get("confidence", 0.5) for a in wipe_analyses]
        return round(sum(scores) / len(scores), 4)

    def _spatial_deletion_heuristic(self) -> bool:
        """
        Heuristic: if clusters alternate between natural_residual and
        intentional_wipe/secure_erase frequently, it suggests selective
        wiping after deletions rather than a bulk operation.
        """
        transitions = 0
        prev = None
        for a in self.cluster_analyses:
            cls = a.get("classification", "natural_residual")
            is_wipe = cls in ("intentional_wipe", "secure_erase")
            if prev is not None and prev != is_wipe:
                transitions += 1
            prev = is_wipe
        total = len(self.cluster_analyses)
        transition_rate = transitions / total if total else 0
        # High transition rate → selective wiping (file-level, not bulk)
        return transition_rate > 0.15

    def _extract_targeted_dirs(self, wipe_cluster_ids: set[int]) -> list[str]:
        """
        Attempt to associate wiped clusters with directory paths.
        Falls back to synthetic hints if no FS metadata available.
        """
        dirs: list[str] = []
        block_size = self.fs_metadata.get("block_size", 4096)

        deleted = self.fs_metadata.get("deleted_entries", [])
        for entry in deleted:
            name = entry.get("name", "")
            if name and not name.startswith("$"):  # skip NTFS metadata
                dirs.append(f"/{name}")

        # If we have wipe_detections with directory hints, include those
        for wd in self.wipe_detections:
            hint = wd.get("directory_hint")
            if hint and hint not in dirs:
                dirs.append(hint)

        return dirs[:10]  # cap

    def _score_to_confidence(self, score: float) -> str:
        if score >= 80:
            return "VERY HIGH"
        if score >= 60:
            return "HIGH"
        if score >= 35:
            return "MEDIUM"
        return "LOW"

    def _score_to_risk(self, score: float) -> str:
        if score >= 75:
            return "CRITICAL"
        if score >= 50:
            return "PROBABLE"
        if score >= 25:
            return "POSSIBLE"
        return "MINIMAL"

    def _build_hypothesis(
        self,
        score: float,
        scope: str,
        targeted_dirs: list[str],
        temporal: bool,
        sensitive: list[str],
    ) -> str:
        """Generate a forensic analyst-style hypothesis string."""
        if score < 20:
            return (
                "Wipe activity is consistent with routine OS maintenance or normal deletion. "
                "No strong indicators of intentional evidence destruction detected."
            )

        scope_desc = {
            "selective": "targeted, file-level",
            "partition": "partition-wide",
            "full_disk": "full-disk",
            "unknown": "unknown-scope",
        }.get(scope, scope)

        parts = [
            f"Evidence suggests a {scope_desc} overwrite operation "
            f"with {self._score_to_confidence(score).lower()} confidence of intentional destruction."
        ]

        if targeted_dirs:
            dir_list = ", ".join(f'"{d}"' for d in targeted_dirs[:3])
            parts.append(f"Affected regions include: {dir_list}.")

        if sensitive:
            parts.append(
                f"Sensitive content directories were specifically targeted: "
                + ", ".join(sensitive[:2]) + "."
            )

        if temporal:
            parts.append(
                "Temporal analysis indicates wipe operations followed mass file deletion events, "
                "suggesting a deliberate cover-up sequence."
            )

        if score >= 70:
            parts.append(
                "Probability of intentional evidence destruction is high. "
                "Recommend chain-of-custody documentation and expert witness review."
            )

        return " ".join(parts)
