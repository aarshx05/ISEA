"""
Cluster Scanner — Pipeline Orchestrator

Coordinates the full analysis pipeline:
  DiskAnalyzer → EntropyEngine → SignatureMatcher → IntentModeler → ScanResult

This is the main entry point for programmatic use.
"""

import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from core.disk_analyzer import DiskAnalyzer
from core.entropy_engine import EntropyEngine
from core.intent_modeler import IntentModeler
from signatures.wipe_signatures import SignatureMatcher
from agent.pipeline_agent import PipelineAgent


@dataclass
class WipeDetection:
    """A single detected wipe region."""
    start_cluster: int
    end_cluster: int
    cluster_count: int
    classification: str          # intentional_wipe | secure_erase
    mean_entropy: float
    tool_match: str              # Best matching tool name
    tool_id: str
    algorithm: str
    pass_count: int
    confidence: float            # 0.0–1.0
    fill_byte: int | None = None
    directory_hint: str | None = None

    def to_dict(self) -> dict:
        return {
            "start_cluster": self.start_cluster,
            "end_cluster": self.end_cluster,
            "cluster_count": self.cluster_count,
            "classification": self.classification,
            "mean_entropy": self.mean_entropy,
            "tool_match": self.tool_match,
            "tool_id": self.tool_id,
            "algorithm": self.algorithm,
            "pass_count": self.pass_count,
            "confidence": self.confidence,
            "fill_byte": f"0x{self.fill_byte:02X}" if self.fill_byte is not None else None,
            "directory_hint": self.directory_hint,
        }


@dataclass
class ScanResult:
    """Complete scan result returned by ClusterScanner."""
    image_path: str
    total_clusters: int
    analyzed_clusters: int
    cluster_size: int
    image_size_bytes: int
    wipe_detections: list[WipeDetection] = field(default_factory=list)
    signature_matches: list[dict] = field(default_factory=list)
    intent_assessment: dict = field(default_factory=dict)
    cluster_analyses: list[dict] = field(default_factory=list)
    region_stats: dict = field(default_factory=dict)
    activity_log: list[dict] = field(default_factory=list)
    evidence_score: float = 0.0          # 0–100
    scan_duration_seconds: float = 0.0
    scan_step: int = 1                   # sampling step used
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "image_path": self.image_path,
            "total_clusters": self.total_clusters,
            "analyzed_clusters": self.analyzed_clusters,
            "cluster_size": self.cluster_size,
            "image_size_bytes": self.image_size_bytes,
            "image_size_mb": round(self.image_size_bytes / (1024 * 1024), 2),
            "wipe_detections": [w.to_dict() for w in self.wipe_detections],
            "signature_matches": self.signature_matches,
            "intent_assessment": self.intent_assessment,
            "region_stats": self.region_stats,
            "activity_log": self.activity_log,
            "evidence_score": self.evidence_score,
            "scan_duration_seconds": round(self.scan_duration_seconds, 2),
            "scan_step": self.scan_step,
            "error": self.error,
        }


class ClusterScanner:
    """
    Orchestrates the full ISEA analysis pipeline for a disk image.

    Usage:
        scanner = ClusterScanner("image.dd")
        result = scanner.run_full_scan()
        print(result.evidence_score)
    """

    def __init__(
        self,
        image_path: str,
        cluster_size: int | None = None,
        progress_callback=None,
        cluster_event_callback=None,
    ):
        """
        Args:
            image_path:             Path to the disk image file.
            cluster_size:           Override cluster size (bytes). Defaults to config.
            progress_callback:      Optional callable(current, total) for progress updates.
            cluster_event_callback: Optional callable(cluster_id, analysis_dict) fired per cluster.
                                    Used by the web UI to stream live classification events.
        """
        self.image_path = image_path
        self.cluster_size = cluster_size
        self.progress_callback = progress_callback
        self.cluster_event_callback = cluster_event_callback
        self.agent_thought_callback = None
        self.agent_question_callback = None
        self._engine = EntropyEngine()
        self._matcher = SignatureMatcher()

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def run_full_scan(self, step: int = 1) -> ScanResult:
        """
        Execute the complete analysis pipeline.

        Args:
            step: Cluster sampling step. 1 = every cluster (thorough),
                  4 = every 4th cluster (faster, less precise).

        Returns:
            ScanResult with all findings populated.
        """
        start_time = time.time()

        try:
            with DiskAnalyzer(self.image_path, self.cluster_size) as disk:
                summary = disk.summary()
                fs_metadata = disk.get_filesystem_metadata()

                # --- 1. Cluster Scan ---
                t1 = time.time()
                cluster_analyses = self._scan_all_clusters(disk, step)
                d1 = time.time() - t1

                # --- 2. Post-processing ---
                t2 = time.time()
                region_stats = self._engine.aggregate_region_stats(cluster_analyses)
                wipe_detections = self._extract_wipe_regions(cluster_analyses)
                signature_matches = self._classify_signatures(cluster_analyses, wipe_detections)
                d2 = time.time() - t2

                # --- 3. Intent & Scoring (Agentic) ---
                t3 = time.time()
                agent = PipelineAgent(
                    agent_thought_callback=self.agent_thought_callback,
                    agent_question_callback=self.agent_question_callback
                )
                intent = self._run_intent_model(fs_metadata, cluster_analyses, wipe_detections, agent)
                evidence_score = self._compute_evidence_score(
                    region_stats, intent, wipe_detections
                )
                d3 = time.time() - t3

                print(f"[Profiling] {Path(self.image_path).name}: "
                      f"Scan={d1:.2f}s, Post={d2:.2f}s, Intent={d3:.2f}s", file=sys.stderr)

            elapsed = time.time() - start_time
            return ScanResult(
                image_path=self.image_path,
                total_clusters=summary["total_clusters"],
                analyzed_clusters=len(cluster_analyses),
                cluster_size=summary["cluster_size"],
                image_size_bytes=summary["image_size_bytes"],
                wipe_detections=wipe_detections,
                signature_matches=signature_matches,
                intent_assessment=intent,
                cluster_analyses=cluster_analyses,
                region_stats=region_stats,
                evidence_score=evidence_score,
                scan_duration_seconds=elapsed,
                scan_step=step,
            )

        except Exception as exc:
            elapsed = time.time() - start_time
            return ScanResult(
                image_path=self.image_path,
                total_clusters=0,
                analyzed_clusters=0,
                cluster_size=self.cluster_size or 4096,
                image_size_bytes=0,
                scan_duration_seconds=elapsed,
                error=str(exc),
            )

    def scan_region(self, start: int, end: int) -> list[dict]:
        """
        Analyze a specific cluster range and return per-cluster classification dicts.
        Useful for targeted follow-up analysis after a quick scan.
        """
        with DiskAnalyzer(self.image_path, self.cluster_size) as disk:
            analyses = []
            for cid, data in disk.iter_clusters(start=start, end=end):
                analysis = self._engine.classify_region(data)
                analysis["cluster_id"] = cid
                analyses.append(analysis)
        return analyses

    def get_summary(self, result: ScanResult) -> dict:
        """Return a compact summary dict suitable for the AI agent's context."""
        wipe_classes = {}
        for w in result.wipe_detections:
            wipe_classes[w.tool_match] = wipe_classes.get(w.tool_match, 0) + 1

        top_tools = sorted(wipe_classes.items(), key=lambda x: x[1], reverse=True)

        return {
            "image": Path(result.image_path).name,
            "size_mb": round(result.image_size_bytes / (1024 * 1024), 2),
            "total_clusters": result.total_clusters,
            "analyzed_clusters": result.analyzed_clusters,
            "wipe_regions_detected": len(result.wipe_detections),
            "top_tools_detected": top_tools[:3],
            "evidence_score": result.evidence_score,
            "risk_level": result.intent_assessment.get("risk_level", "UNKNOWN"),
            "wipe_scope": result.intent_assessment.get("wipe_scope", "unknown"),
            "mean_entropy": result.region_stats.get("mean_entropy", 0.0),
            "wipe_fraction": result.region_stats.get("wipe_fraction", 0.0),
            "scan_duration_s": result.scan_duration_seconds,
            "classification_breakdown": result.region_stats.get("by_classification", {}),
        }

    # ------------------------------------------------------------------ #
    # Pipeline stages
    # ------------------------------------------------------------------ #

    def _scan_all_clusters(self, disk: DiskAnalyzer, step: int) -> list[dict]:
        """Iterate all clusters and classify each one."""
        total = disk.get_cluster_count()
        analyses: list[dict] = []

        for cid, data in disk.iter_clusters(step=step):
            analysis = self._engine.classify_region(data)
            analysis["cluster_id"] = cid
            analyses.append(analysis)

            if self.progress_callback:
                self.progress_callback(cid + 1, total)

            if self.cluster_event_callback:
                self.cluster_event_callback(cid, analysis)

        return analyses

    def _extract_wipe_regions(self, cluster_analyses: list[dict]) -> list[WipeDetection]:
        """
        Merge contiguous wiped clusters into WipeDetection regions.
        A region break occurs when classification returns to natural/os_clear.
        """
        detections: list[WipeDetection] = []
        current_region: list[dict] = []
        region_start = 0

        def _flush_region(region: list[dict], start: int) -> WipeDetection | None:
            if not region:
                return None
            entropies = [a["entropy"] for a in region]
            mean_e = sum(entropies) / len(entropies)
            fill_bytes = [a["fill_byte"] for a in region if a.get("fill_byte") is not None]
            fill_byte = fill_bytes[0] if fill_bytes else None
            cls_votes = {}
            for a in region:
                c = a.get("classification", "natural_residual")
                cls_votes[c] = cls_votes.get(c, 0) + 1
            dominant_cls = max(cls_votes, key=cls_votes.get)
            mean_conf = sum(a.get("confidence", 0.5) for a in region) / len(region)

            sig = self._matcher.classify_wipe_algorithm(region)
            end_cluster = start + len(region) - 1

            return WipeDetection(
                start_cluster=start,
                end_cluster=end_cluster,
                cluster_count=len(region),
                classification=dominant_cls,
                mean_entropy=round(mean_e, 4),
                tool_match=sig["tool"],
                tool_id=sig["tool_id"],
                algorithm=sig["algorithm"],
                pass_count=sig["pass_count"],
                confidence=round(mean_conf, 4),
                fill_byte=fill_byte,
            )

        for analysis in cluster_analyses:
            cls = analysis.get("classification", "natural_residual")
            cid = analysis.get("cluster_id", len(detections))

            if cls in ("intentional_wipe", "secure_erase"):
                if not current_region:
                    region_start = cid
                current_region.append(analysis)
            else:
                if current_region:
                    det = _flush_region(current_region, region_start)
                    if det:
                        detections.append(det)
                    current_region = []

        if current_region:
            det = _flush_region(current_region, region_start)
            if det:
                detections.append(det)

        return detections

    def _classify_signatures(
        self, cluster_analyses: list[dict], wipe_detections: list[WipeDetection]
    ) -> list[dict]:
        """Return top-level signature match summary across all wipe regions."""
        if not wipe_detections:
            return []

        # Aggregate evidence from all wipe regions
        all_wipe_analyses = [
            a for a in cluster_analyses
            if a.get("classification") in ("intentional_wipe", "secure_erase")
        ]
        if not all_wipe_analyses:
            return []

        overall = self._matcher.classify_wipe_algorithm(all_wipe_analyses)
        incomplete = self._matcher.detect_incomplete_wipe(cluster_analyses)

        return [
            {
                "scope": "full_image",
                **overall,
                "incomplete_wipe": incomplete,
            }
        ]

    def _run_intent_model(
        self,
        fs_metadata: dict,
        cluster_analyses: list[dict],
        wipe_detections: list[WipeDetection],
        agent: PipelineAgent,
    ) -> dict:
        wipe_dicts = [w.to_dict() for w in wipe_detections]
        modeler = IntentModeler(
            fs_metadata=fs_metadata,
            cluster_analyses=cluster_analyses,
            wipe_detections=wipe_dicts,
            agent=agent,
        )
        return modeler.compute_intent_score()

    def _compute_evidence_score(
        self,
        region_stats: dict,
        intent: dict,
        wipe_detections: list[WipeDetection],
    ) -> float:
        """
        Composite 0–100 evidence score for forensic reporting.

        Factors:
          40% — intent score (behavioral)
          30% — wipe fraction of disk
          20% — wipe confidence (signature match quality)
          10% — number of distinct wipe regions detected
        """
        intent_score = intent.get("score", 0.0)  # 0–100
        wipe_fraction = region_stats.get("wipe_fraction", 0.0)  # 0–1
        mean_conf = (
            sum(w.confidence for w in wipe_detections) / len(wipe_detections)
            if wipe_detections else 0.0
        )
        region_count_factor = min(len(wipe_detections) / 10.0, 1.0)

        score = (
            0.40 * intent_score
            + 0.30 * (wipe_fraction * 100)
            + 0.20 * (mean_conf * 100)
            + 0.10 * (region_count_factor * 100)
        )
        return round(min(score, 100.0), 1)
