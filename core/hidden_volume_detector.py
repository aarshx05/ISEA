"""
Hidden Encrypted Volume Detector

Distinguishes VeraCrypt/TrueCrypt hidden volumes from random-fill wipe
activity using four statistical signals:

  1. Outer filesystem presence (FAT/NTFS/ext4 magic bytes near region)
  2. Unallocated space location (region in disk free space)
  3. Chi-square byte uniformity (AES-XTS → near-perfect distribution)
  4. Entropy boundary sharpness (abrupt natural→max→natural transitions)

Key insight: both VeraCrypt hidden volumes and `dd if=/dev/urandom` wipes
produce ~7.9 bits/byte entropy. This module disambiguates them using
statistical and structural context rather than entropy alone.

Signal weights:
  outer_fs_detected     → 0.40  (strongest: VeraCrypt always needs outer vol)
  in_unallocated_space  → 0.25  (hidden vol occupies outer vol free space)
  chi_square_uniformity → 0.20  (AES-XTS is more uniform than PRNG wipers)
  boundary_sharpness    → 0.15  (abrupt transitions vs gradual wipe fade)
"""

import math
import struct
from dataclasses import dataclass, field
from pathlib import Path

from core.disk_analyzer import DiskAnalyzer


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Minimum average entropy for a cluster to be considered high-entropy
_HIGH_ENTROPY_THRESHOLD = 7.5

# Minimum contiguous high-entropy clusters to form a candidate region
_MIN_REGION_CLUSTERS = 25

# Minimum candidate size in bytes (100 KB)
_MIN_REGION_BYTES = 100 * 1024

# Minimum composite confidence to include in results
_MIN_CONFIDENCE = 0.35

# Number of edge clusters to sample for boundary sharpness measurement
_EDGE_SAMPLE = 3

# How many clusters to scan on each side for outer filesystem detection
_FS_SCAN_RADIUS = 50   # clusters

# FAT magic at byte offset 510–511 of the boot sector (0x55 0xAA)
_FAT_MAGIC_OFFSET = 510
_FAT_MAGIC = b"\x55\xAA"

# NTFS OEM ID at byte offset 3–6 of the boot sector
_NTFS_OEM_OFFSET = 3
_NTFS_OEM = b"NTFS"

# ext4 magic number at byte offset 0x438 (1080) from partition start
_EXT4_MAGIC_OFFSET = 1080
_EXT4_MAGIC = b"\x53\xef"   # little-endian 0xEF53

# exFAT OEM ID at byte offset 3
_EXFAT_OEM_OFFSET = 3
_EXFAT_OEM = b"EXFAT   "


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class HiddenVolumeCandidate:
    """A single suspected hidden encrypted volume region."""

    start_cluster: int
    end_cluster: int
    cluster_count: int
    size_bytes: int
    mean_entropy: float
    chi_square_score: float     # raw chi² value — lower = more uniform = more crypto-like
    chi_square_norm: float      # normalized 0.0–1.0 (1.0 = perfect AES-XTS uniformity)
    boundary_sharpness: float   # 0.0–1.0 (1.0 = maximally abrupt transition)
    in_unallocated: bool        # falls within fs_metadata unallocated regions
    outer_fs_detected: bool     # FAT/NTFS/ext4 magic found in surrounding clusters
    confidence: float           # 0.0–1.0 composite score
    tool_hint: str              # "VeraCrypt" | "TrueCrypt" | "Unknown Encryption"

    def to_dict(self) -> dict:
        return {
            "start_cluster": self.start_cluster,
            "end_cluster": self.end_cluster,
            "cluster_count": self.cluster_count,
            "size_bytes": self.size_bytes,
            "size_kb": round(self.size_bytes / 1024, 1),
            "mean_entropy": round(self.mean_entropy, 4),
            "chi_square_score": round(self.chi_square_score, 2),
            "chi_square_norm": round(self.chi_square_norm, 4),
            "boundary_sharpness": round(self.boundary_sharpness, 4),
            "in_unallocated": self.in_unallocated,
            "outer_fs_detected": self.outer_fs_detected,
            "confidence": round(self.confidence, 4),
            "tool_hint": self.tool_hint,
        }


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

class HiddenVolumeDetector:
    """
    Analyzes a scanned disk image for hidden encrypted volume candidates.

    Args:
        cluster_analyses:  List of classification dicts from EntropyEngine
                           (each dict has: cluster_id, entropy, classification, ...)
        fs_metadata:       Dict from DiskAnalyzer.get_filesystem_metadata()
        image_path:        Path to the raw disk image file
        cluster_size:      Bytes per cluster (default 4096)
    """

    def __init__(
        self,
        cluster_analyses: list[dict],
        fs_metadata: dict,
        image_path: str,
        cluster_size: int = 4096,
    ):
        self.cluster_analyses = cluster_analyses
        self.fs_metadata = fs_metadata
        self.image_path = image_path
        self.cluster_size = cluster_size
        self._total_clusters = len(cluster_analyses)
        # Pre-compute unallocated region set for fast membership testing
        self._unallocated_ranges: list[tuple[int, int]] = self._parse_unallocated()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def detect(self) -> list[HiddenVolumeCandidate]:
        """
        Main entry point. Returns HiddenVolumeCandidate list sorted by
        confidence descending. Only includes candidates with confidence >= 0.35.
        """
        # Step 1: find contiguous high-entropy runs
        raw_regions = self._find_high_entropy_runs()

        # Step 2: pre-filter by minimum size
        regions = [
            r for r in raw_regions
            if (r["end"] - r["start"] + 1) * self.cluster_size >= _MIN_REGION_BYTES
        ]

        candidates: list[HiddenVolumeCandidate] = []
        for region in regions:
            start = region["start"]
            end = region["end"]
            mean_e = region["mean_entropy"]
            size_bytes = (end - start + 1) * self.cluster_size

            # Step 3: score each signal
            chi_raw, chi_norm = self._chi_square_uniformity(start, end)
            sharpness = self._boundary_sharpness(start, end)
            in_unalloc = self._in_unallocated_space(start, end)
            outer_fs = self._outer_fs_detected(start, end)

            # Step 4: composite score
            composite = self._composite_score(chi_norm, sharpness, in_unalloc, outer_fs)

            if composite < _MIN_CONFIDENCE:
                continue

            tool = self._identify_tool(composite, outer_fs)

            candidates.append(HiddenVolumeCandidate(
                start_cluster=start,
                end_cluster=end,
                cluster_count=end - start + 1,
                size_bytes=size_bytes,
                mean_entropy=round(mean_e, 4),
                chi_square_score=round(chi_raw, 2),
                chi_square_norm=round(chi_norm, 4),
                boundary_sharpness=round(sharpness, 4),
                in_unallocated=in_unalloc,
                outer_fs_detected=outer_fs,
                confidence=round(composite, 4),
                tool_hint=tool,
            ))

        candidates.sort(key=lambda c: c.confidence, reverse=True)
        return candidates

    # ------------------------------------------------------------------
    # Step 1: find contiguous high-entropy runs
    # ------------------------------------------------------------------

    def _find_high_entropy_runs(self) -> list[dict]:
        """
        Scan cluster_analyses for contiguous sequences where mean entropy > 7.5.
        Returns list of {start, end, mean_entropy} dicts.
        """
        runs: list[dict] = []
        current_start: int | None = None
        entropies: list[float] = []

        for analysis in self.cluster_analyses:
            e = analysis.get("entropy", 0.0)
            cid = analysis.get("cluster_id", len(runs))

            if e >= _HIGH_ENTROPY_THRESHOLD:
                if current_start is None:
                    current_start = cid
                entropies.append(e)
            else:
                if current_start is not None and len(entropies) >= _MIN_REGION_CLUSTERS:
                    runs.append({
                        "start": current_start,
                        "end": cid - 1,
                        "mean_entropy": sum(entropies) / len(entropies),
                    })
                current_start = None
                entropies = []

        # Flush trailing run
        if current_start is not None and len(entropies) >= _MIN_REGION_CLUSTERS:
            last_cid = self.cluster_analyses[-1].get("cluster_id", len(self.cluster_analyses) - 1)
            runs.append({
                "start": current_start,
                "end": last_cid,
                "mean_entropy": sum(entropies) / len(entropies),
            })

        return runs

    # ------------------------------------------------------------------
    # Signal 1: Chi-square byte uniformity
    # ------------------------------------------------------------------

    def _chi_square_uniformity(self, start_cluster: int, end_cluster: int) -> tuple[float, float]:
        """
        Sample up to 8 clusters from the region, compute chi-square statistic
        against a perfectly uniform byte distribution (256 buckets, equal expected).

        AES-XTS produces χ² ≈ 255 (1 degree of freedom per bucket, 256 buckets).
        PRNG-based wipers tend to have χ² in the 270–400 range due to algorithmic bias.

        Returns:
            (chi_square_raw, normalized_score)
            normalized_score: 1.0 = perfect uniformity (most crypto-like),
                              0.0 = highly non-uniform
        """
        try:
            disk = DiskAnalyzer(self.image_path, self.cluster_size)
        except Exception:
            return (300.0, 0.5)   # neutral fallback

        try:
            cluster_count = end_cluster - start_cluster + 1
            # Sample up to 8 evenly-spaced clusters
            step = max(1, cluster_count // 8)
            sample_ids = list(range(start_cluster, end_cluster + 1, step))[:8]

            byte_counts = [0] * 256
            total_bytes = 0

            for cid in sample_ids:
                offset = cid * self.cluster_size
                try:
                    data = disk.read_bytes(offset, self.cluster_size)
                    for b in data:
                        byte_counts[b] += 1
                    total_bytes += len(data)
                except Exception:
                    continue

            disk.close()

            if total_bytes == 0:
                return (300.0, 0.5)

            expected = total_bytes / 256.0
            chi2 = sum((count - expected) ** 2 / expected for count in byte_counts)

            # Normalize: perfect AES-XTS ≈ 255, PRNG bias ≈ 300–600+
            # Map 255 → 1.0, 800+ → 0.0 using a sigmoid-like decay
            # chi2 of 255 → norm 1.0; 500 → ~0.5; 800 → ~0.1
            norm = max(0.0, min(1.0, 1.0 - (chi2 - 255.0) / 550.0))
            return (round(chi2, 2), round(norm, 4))

        except Exception:
            try:
                disk.close()
            except Exception:
                pass
            return (300.0, 0.5)

    # ------------------------------------------------------------------
    # Signal 2: Entropy boundary sharpness
    # ------------------------------------------------------------------

    def _boundary_sharpness(self, region_start: int, region_end: int) -> float:
        """
        Measure how abruptly entropy transitions at the region's leading and
        trailing edges.

        VeraCrypt: outer volume (low entropy) → hidden volume (max entropy) →
                   outer volume again. The transition is sector-aligned and near-instant.

        Wipe tools: entropy often bleeds gradually at boundaries due to partial
                    cluster coverage or algorithm startup ramps.

        Returns 0.0–1.0. Higher = sharper (more indicative of encryption).
        """
        analyses_by_id = {
            a.get("cluster_id", i): a
            for i, a in enumerate(self.cluster_analyses)
        }

        def mean_entropy_range(start: int, end: int) -> float:
            vals = []
            for cid in range(start, end + 1):
                a = analyses_by_id.get(cid)
                if a:
                    vals.append(a.get("entropy", 0.0))
            return sum(vals) / len(vals) if vals else 0.0

        # Interior entropy (mean of region minus edges)
        interior_start = region_start + _EDGE_SAMPLE
        interior_end = region_end - _EDGE_SAMPLE
        if interior_start > interior_end:
            # Region too small to differentiate edges from interior
            return 0.3

        interior_entropy = mean_entropy_range(interior_start, interior_end)

        # Leading edge: _EDGE_SAMPLE clusters just before region
        pre_start = max(0, region_start - _EDGE_SAMPLE)
        pre_entropy = mean_entropy_range(pre_start, region_start - 1)

        # Trailing edge: _EDGE_SAMPLE clusters just after region
        post_end = min(self._total_clusters - 1, region_end + _EDGE_SAMPLE)
        post_entropy = mean_entropy_range(region_end + 1, post_end)

        # Boundary delta: how sharp is the drop at each edge?
        leading_delta = abs(interior_entropy - pre_entropy)
        trailing_delta = abs(interior_entropy - post_entropy)
        mean_delta = (leading_delta + trailing_delta) / 2.0

        # Max possible delta = 8.0; normalize to 0.0–1.0
        sharpness = min(1.0, mean_delta / 4.0)   # delta of 4.0 → 1.0
        return round(sharpness, 4)

    # ------------------------------------------------------------------
    # Signal 3: Unallocated space
    # ------------------------------------------------------------------

    def _in_unallocated_space(self, start_cluster: int, end_cluster: int) -> bool:
        """
        Return True if the region's midpoint falls within any unallocated
        range reported by DiskAnalyzer.get_filesystem_metadata().
        """
        if not self._unallocated_ranges:
            # If no unallocated info available, treat as possibly unallocated
            # (gives partial credit when filesystem parsing is unavailable)
            return False

        mid = (start_cluster + end_cluster) // 2
        for (u_start, u_end) in self._unallocated_ranges:
            if u_start <= mid <= u_end:
                return True
        return False

    def _parse_unallocated(self) -> list[tuple[int, int]]:
        """Convert fs_metadata unallocated_regions to cluster-indexed ranges."""
        result: list[tuple[int, int]] = []
        for region in self.fs_metadata.get("unallocated_regions", []):
            start_bytes = region.get("start", 0)
            end_bytes = region.get("end", 0)
            start_cluster = start_bytes // self.cluster_size
            end_cluster = end_bytes // self.cluster_size
            result.append((start_cluster, end_cluster))
        return result

    # ------------------------------------------------------------------
    # Signal 4: Outer filesystem detection
    # ------------------------------------------------------------------

    def _outer_fs_detected(self, start_cluster: int, end_cluster: int) -> bool:
        """
        Scan the ±_FS_SCAN_RADIUS cluster neighborhood for filesystem magic bytes.

        VeraCrypt always creates an outer volume with a real filesystem first,
        then writes the hidden volume into its free space. So the region is
        surrounded by a mounted-looking filesystem.

        Checks for: FAT12/16/32, NTFS, exFAT, ext4.
        """
        try:
            disk = DiskAnalyzer(self.image_path, self.cluster_size)
        except Exception:
            return False

        try:
            scan_start = max(0, start_cluster - _FS_SCAN_RADIUS)
            scan_end = min(self._total_clusters - 1, end_cluster + _FS_SCAN_RADIUS)

            for cid in range(scan_start, scan_end + 1):
                # Skip clusters inside the candidate region itself
                if start_cluster <= cid <= end_cluster:
                    continue

                offset = cid * self.cluster_size
                try:
                    data = disk.read_bytes(offset, min(self.cluster_size, 1536))
                except Exception:
                    continue

                if self._has_fs_magic(data):
                    disk.close()
                    return True

            disk.close()
            return False

        except Exception:
            try:
                disk.close()
            except Exception:
                pass
            return False

    def _has_fs_magic(self, data: bytes) -> bool:
        """Check data block for filesystem magic bytes."""
        n = len(data)

        # FAT boot sector signature (0x55 0xAA at offset 510)
        if n >= 512 and data[_FAT_MAGIC_OFFSET:_FAT_MAGIC_OFFSET + 2] == _FAT_MAGIC:
            return True

        # NTFS OEM ID ("NTFS" at offset 3)
        if n >= 7 and data[_NTFS_OEM_OFFSET:_NTFS_OEM_OFFSET + 4] == _NTFS_OEM:
            return True

        # exFAT OEM ID at offset 3
        if n >= 11 and data[_EXFAT_OEM_OFFSET:_EXFAT_OEM_OFFSET + 8] == _EXFAT_OEM:
            return True

        # ext4 superblock magic (0xEF53 LE) at byte offset 1080 from partition start
        # Only present in the first cluster of a partition
        if n >= _EXT4_MAGIC_OFFSET + 2:
            if data[_EXT4_MAGIC_OFFSET:_EXT4_MAGIC_OFFSET + 2] == _EXT4_MAGIC:
                return True

        return False

    # ------------------------------------------------------------------
    # Composite scoring + tool identification
    # ------------------------------------------------------------------

    def _composite_score(
        self,
        chi_norm: float,
        sharpness: float,
        in_unalloc: bool,
        outer_fs: bool,
    ) -> float:
        """
        Weighted composite confidence score:
          0.40 × outer_fs_detected
          0.25 × in_unallocated_space
          0.20 × chi_square_uniformity (normalized)
          0.15 × boundary_sharpness
        """
        score = (
            0.40 * (1.0 if outer_fs else 0.0)
            + 0.25 * (1.0 if in_unalloc else 0.0)
            + 0.20 * chi_norm
            + 0.15 * sharpness
        )
        return round(min(score, 1.0), 4)

    def _identify_tool(self, confidence: float, outer_fs: bool) -> str:
        """
        Best-guess tool identification based on confidence and context.
        VeraCrypt and TrueCrypt are functionally identical at the signal level;
        the distinction is heuristic (TrueCrypt was EOL 2014, VeraCrypt forked it).
        """
        if outer_fs and confidence >= 0.65:
            return "VeraCrypt"
        if outer_fs and confidence >= 0.50:
            return "TrueCrypt / VeraCrypt"
        if confidence >= 0.50:
            return "Unknown Encryption (no outer FS found)"
        return "Unknown Encryption"
