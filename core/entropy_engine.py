"""
Statistical Signature Engine — Shannon entropy, byte distribution analysis,
pattern detection, overwrite consistency scoring, and region classification.

Classification labels:
  natural_residual  — organic file data, OS artifacts
  os_clear          — normal OS zeroing/clearing behavior
  intentional_wipe  — deliberate overwrite (tool-assisted)
  secure_erase      — high-confidence multi-pass cryptographic erasure
"""

import math
from collections import Counter

import numpy as np

from config import config


class EntropyEngine:
    """
    Stateless analysis engine. All methods accept raw bytes and return
    structured dicts or primitive values — no disk I/O involved.
    """

    # ------------------------------------------------------------------ #
    # Entropy & distribution primitives
    # ------------------------------------------------------------------ #

    def shannon_entropy(self, data: bytes) -> float:
        """
        Compute Shannon entropy in bits per byte. Range: [0.0, 8.0].
          0.0 → perfectly uniform (all same byte)
          8.0 → maximally random (uniform distribution across all 256 values)
        """
        if not data:
            return 0.0
        counts = Counter(data)
        length = len(data)
        entropy = 0.0
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        return round(entropy, 6)

    def byte_frequency(self, data: bytes) -> dict[int, int]:
        """Return a full 256-bucket histogram: {byte_value: occurrence_count}."""
        hist = {i: 0 for i in range(256)}
        hist.update(Counter(data))
        return hist

    def byte_variance(self, data: bytes) -> float:
        """
        Variance of byte frequencies across the 256 possible values.
        Near 0  → uniform fill (all bytes equal count)
        High    → skewed distribution (typical of structured data)
        """
        if not data:
            return 0.0
        freq = list(self.byte_frequency(data).values())
        return float(np.var(freq))

    # ------------------------------------------------------------------ #
    # Pattern / fill detection
    # ------------------------------------------------------------------ #

    def detect_uniform_fill(self, data: bytes) -> tuple[bool, int | None]:
        """
        Detect if a buffer is filled entirely with a single repeated byte.

        Returns:
            (True,  fill_byte)  if >99% of bytes are identical
            (False, None)       otherwise
        """
        if not data:
            return False, None
        most_common_byte, count = Counter(data).most_common(1)[0]
        ratio = count / len(data)
        if ratio >= 0.99:
            return True, most_common_byte
        return False, None

    def detect_pattern_repetition(
        self, data: bytes, max_pattern_len: int = 64
    ) -> tuple[bool, bytes | None]:
        """
        Detect if a buffer consists of a short repeating byte sequence.
        e.g. b'\\x00\\xFF\\x00\\xFF...' or b'\\xA5\\x5A...'

        Returns:
            (True,  pattern_bytes)  if a repeating pattern of length 2–max_pattern_len is found
            (False, None)           otherwise
        """
        if len(data) < 4:
            return False, None

        for plen in range(2, min(max_pattern_len + 1, len(data) // 2 + 1)):
            pattern = data[:plen]
            # Check if data is just this pattern repeated
            full_repeats = len(data) // plen
            reconstructed = pattern * full_repeats + pattern[: len(data) % plen]
            if reconstructed == data:
                return True, bytes(pattern)
        return False, None

    def overwrite_consistency_score(self, clusters: list[bytes]) -> float:
        """
        Measure how consistently a set of clusters has been overwritten.
        Used to distinguish single-pass wipes from multi-pass or partial wipes.

        Returns 0.0–1.0:
          1.0 → all clusters have near-identical entropy and fill pattern
          0.0 → highly variable (mixed wiped/unwiped regions)
        """
        if not clusters:
            return 0.0
        entropies = [self.shannon_entropy(c) for c in clusters]
        mean_e = np.mean(entropies)
        std_e = np.std(entropies)
        # Normalize: std near 0 = consistent; std near 4 = highly variable
        consistency = max(0.0, 1.0 - (std_e / 4.0))
        return round(float(consistency), 4)

    def entropy_gradient(self, entropies: list[float]) -> list[float]:
        """
        Compute the first-order gradient (delta) of a sequence of entropy values.
        Sudden transitions (high gradient) indicate wipe boundaries.
        """
        if len(entropies) < 2:
            return []
        return [round(abs(entropies[i] - entropies[i - 1]), 6) for i in range(1, len(entropies))]

    # ------------------------------------------------------------------ #
    # High-level region classifier
    # ------------------------------------------------------------------ #

    def classify_region(self, data: bytes) -> dict:
        """
        Comprehensive analysis of a single cluster or region.

        Returns a dict:
        {
            "classification":  str,    # natural_residual | os_clear | intentional_wipe | secure_erase
            "entropy":         float,  # 0.0 – 8.0
            "confidence":      float,  # 0.0 – 1.0
            "fill_byte":       int | None,
            "fill_pattern":    bytes | None,
            "is_random":       bool,
            "byte_variance":   float,
            "notes":           list[str]
        }
        """
        result: dict = {
            "classification": "natural_residual",
            "entropy": 0.0,
            "confidence": 0.0,
            "fill_byte": None,
            "fill_pattern": None,
            "is_random": False,
            "byte_variance": 0.0,
            "notes": [],
        }

        if not data:
            result["notes"].append("Empty region")
            return result

        entropy = self.shannon_entropy(data)
        variance = self.byte_variance(data)
        is_uniform, fill_byte = self.detect_uniform_fill(data)
        is_pattern, fill_pattern = self.detect_pattern_repetition(data)

        result["entropy"] = entropy
        result["byte_variance"] = round(variance, 2)
        result["fill_byte"] = fill_byte
        result["fill_pattern"] = fill_pattern

        thresholds = config.entropy

        # --- Secure erase: very high entropy, no discernible pattern
        if thresholds.secure_erase[0] <= entropy <= thresholds.secure_erase[1]:
            result["classification"] = "secure_erase"
            result["is_random"] = True
            result["confidence"] = self._entropy_confidence(entropy, *thresholds.secure_erase)
            result["notes"].append(
                f"Entropy {entropy:.2f} → consistent with multi-pass random overwrite"
            )

        # --- Intentional wipe: medium-high entropy or uniform fill pattern
        elif thresholds.intentional_wipe[0] <= entropy < thresholds.secure_erase[0]:
            result["classification"] = "intentional_wipe"
            result["confidence"] = self._entropy_confidence(entropy, *thresholds.intentional_wipe)
            if is_uniform:
                result["notes"].append(
                    f"Uniform fill with byte 0x{fill_byte:02X} — possible zero/FF fill wipe"
                )
            if is_pattern:
                result["notes"].append(
                    f"Repeating byte pattern detected: {fill_pattern.hex()} — structured overwrite"
                )
            result["notes"].append(f"Entropy {entropy:.2f} → consistent with tool-assisted wipe")

        # --- OS clear: moderate entropy, often partial zeroing
        elif thresholds.os_clear[0] <= entropy < thresholds.intentional_wipe[0]:
            result["classification"] = "os_clear"
            result["confidence"] = self._entropy_confidence(entropy, *thresholds.os_clear)
            result["notes"].append(
                f"Entropy {entropy:.2f} → consistent with normal OS clearing or partial deletion"
            )

        # --- Natural residual: low entropy, organic data structure
        else:
            result["classification"] = "natural_residual"
            result["confidence"] = self._entropy_confidence(entropy, *thresholds.natural)
            if is_uniform and fill_byte == 0x00:
                result["notes"].append("Pure zero region — likely uninitialized or OS-zeroed")
            else:
                result["notes"].append(
                    f"Entropy {entropy:.2f} → natural file data or structured content"
                )

        # Extra flag: near-perfect uniformity even in wipe range raises confidence
        if is_uniform and fill_byte is not None:
            result["confidence"] = min(1.0, result["confidence"] + 0.15)
            result["notes"].append(
                f"High uniformity (fill byte 0x{fill_byte:02X}) boosts confidence"
            )

        result["confidence"] = round(result["confidence"], 4)
        return result

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    def _entropy_confidence(self, entropy: float, low: float, high: float) -> float:
        """
        Map entropy into a confidence score within a given band.
        The center of the band yields highest confidence (1.0); edges yield ~0.5.
        """
        center = (low + high) / 2.0
        half_width = (high - low) / 2.0
        if half_width == 0:
            return 1.0
        distance = abs(entropy - center) / half_width
        return round(max(0.5, 1.0 - distance * 0.5), 4)

    def analyze_cluster_batch(self, clusters: list[bytes]) -> list[dict]:
        """Analyze a list of clusters and return per-cluster classification dicts."""
        return [self.classify_region(c) for c in clusters]

    def aggregate_region_stats(self, analyses: list[dict]) -> dict:
        """
        Summarize a batch of cluster analyses into aggregate statistics.

        Returns:
        {
            "total_clusters":     int,
            "by_classification":  dict[str, int],
            "mean_entropy":       float,
            "max_entropy":        float,
            "min_entropy":        float,
            "wipe_fraction":      float,   # fraction of wiped+secure clusters
            "mean_confidence":    float,
            "entropy_gradient":   list[float]
        }
        """
        if not analyses:
            return {}

        entropies = [a["entropy"] for a in analyses]
        classifications = [a["classification"] for a in analyses]
        confidences = [a["confidence"] for a in analyses]

        by_class: dict[str, int] = {}
        for c in classifications:
            by_class[c] = by_class.get(c, 0) + 1

        wipe_count = by_class.get("intentional_wipe", 0) + by_class.get("secure_erase", 0)
        total = len(analyses)

        return {
            "total_clusters": total,
            "by_classification": by_class,
            "mean_entropy": round(float(np.mean(entropies)), 4),
            "max_entropy": round(float(np.max(entropies)), 4),
            "min_entropy": round(float(np.min(entropies)), 4),
            "wipe_fraction": round(wipe_count / total, 4) if total else 0.0,
            "mean_confidence": round(float(np.mean(confidences)), 4),
            "entropy_gradient": self.entropy_gradient(entropies),
        }
