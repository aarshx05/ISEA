"""
Synthetic Disk Image Factory

Creates small in-memory or on-disk fake disk images for testing
without requiring a real disk image. All images are raw binary blobs.
"""

import os
import random
import struct
import tempfile
from pathlib import Path


MB = 1024 * 1024
CLUSTER_SIZE = 4096


class SyntheticDiskFactory:
    """
    Generates synthetic disk images representing various wipe scenarios.
    Images are written to a temp directory by default or returned as bytes.
    """

    def __init__(self, output_dir: str | Path | None = None):
        self.output_dir = Path(output_dir) if output_dir else Path(tempfile.gettempdir()) / "isea_test"
        self.output_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ #
    # Image generators (return bytes)
    # ------------------------------------------------------------------ #

    @staticmethod
    def create_zero_filled_image(size_mb: int = 1) -> bytes:
        """Pure zero-fill — simulates dd if=/dev/zero or sdelete."""
        return bytes(size_mb * MB)

    @staticmethod
    def create_ff_filled_image(size_mb: int = 1) -> bytes:
        """0xFF-filled — one of the DBAN passes."""
        return bytes([0xFF]) * (size_mb * MB)

    @staticmethod
    def create_random_filled_image(size_mb: int = 1) -> bytes:
        """Cryptographic-quality random fill — simulates dd if=/dev/urandom."""
        return os.urandom(size_mb * MB)

    @staticmethod
    def create_natural_data_image(size_mb: int = 1) -> bytes:
        """
        Simulates natural file data: mix of text, binary, and zero padding.
        Produces a non-suspicious entropy profile (~3.0–5.0).
        """
        total = size_mb * MB
        chunk_size = CLUSTER_SIZE
        chunks = []
        rng = random.Random(42)  # deterministic for test reproducibility

        for _ in range(total // chunk_size):
            kind = rng.choice(["text", "binary", "zero"])
            if kind == "text":
                # Simulate ASCII text content
                words = ["the", "quick", "brown", "fox", "jumps", "over",
                         "finance", "report", "confidential", "deleted"]
                text = " ".join(rng.choice(words) for _ in range(200))
                chunk = (text.encode("ascii") * ((chunk_size // len(text)) + 1))[:chunk_size]
            elif kind == "binary":
                chunk = bytes([rng.randint(0, 127) for _ in range(chunk_size)])
            else:
                chunk = bytes(chunk_size)
            chunks.append(chunk)

        return b"".join(chunks)

    @staticmethod
    def create_mixed_image(size_mb: int = 2, wipe_fraction: float = 0.5) -> bytes:
        """
        Mix of natural data and random-wiped clusters.
        Simulates a selective wipe targeting ~50% of the disk.
        """
        total = size_mb * MB
        chunk_size = CLUSTER_SIZE
        cluster_count = total // chunk_size
        wipe_count = int(cluster_count * wipe_fraction)

        rng = random.Random(99)
        wiped_indices = set(rng.sample(range(cluster_count), wipe_count))

        chunks = []
        for i in range(cluster_count):
            if i in wiped_indices:
                chunks.append(os.urandom(chunk_size))
            else:
                # Natural data
                text = f"cluster{i} natural data file content header body"
                chunk = (text.encode() * (chunk_size // len(text) + 1))[:chunk_size]
                chunks.append(chunk)

        return b"".join(chunks)

    @staticmethod
    def create_dod_pattern_image(size_mb: int = 1) -> bytes:
        """
        Simulates a DoD 3-pass wipe (zero → FF → random).
        The final state visible on disk is the last pass: random.
        """
        # Final visible state is random (last pass wins)
        return os.urandom(size_mb * MB)

    @staticmethod
    def create_selective_wipe_image(size_mb: int = 4) -> bytes:
        """
        Simulates a targeted wipe: only the middle third of the disk is wiped.
        Mimics an attacker selectively erasing specific file regions.
        """
        total = size_mb * MB
        third = total // 3
        # First and last thirds: natural data
        start_region = SyntheticDiskFactory.create_natural_data_image(size_mb // 3 or 1)[:third]
        end_region = SyntheticDiskFactory.create_natural_data_image(size_mb // 3 or 1)[:third]
        # Middle third: random wipe
        wiped_region = os.urandom(total - 2 * third)
        return start_region + wiped_region + end_region

    @staticmethod
    def create_realistic_image(size_mb: int = 4) -> bytes:
        """
        Realistic scenario: mostly natural data, 20% targeted wipe in the
        second quarter of disk (simulating finance directory erasure).
        """
        total = size_mb * MB
        cluster_count = total // CLUSTER_SIZE
        # 25%–50% of clusters are wiped
        wipe_start = cluster_count // 4
        wipe_end = cluster_count // 2

        chunks = []
        for i in range(cluster_count):
            if wipe_start <= i < wipe_end:
                # Wiped region — random fill (urandom)
                chunks.append(os.urandom(CLUSTER_SIZE))
            else:
                # Natural data
                txt = f"file data content cluster {i} report summary page"
                chunk = (txt.encode() * (CLUSTER_SIZE // len(txt) + 1))[:CLUSTER_SIZE]
                chunks.append(chunk)

        return b"".join(chunks)

    @staticmethod
    def create_incomplete_wipe_image(size_mb: int = 2) -> bytes:
        """
        Simulates an interrupted wipe: the first half is wiped, second half intact.
        Common when attacker was interrupted or tool crashed.
        """
        total = size_mb * MB
        half = total // 2
        wiped = os.urandom(half)
        natural_text = b"Evidence preserved intact. Original file data remains." * (half // 54 + 1)
        natural = natural_text[:half]
        return wiped + natural

    # ------------------------------------------------------------------ #
    # File persistence helpers
    # ------------------------------------------------------------------ #

    def write_image(self, name: str, data: bytes) -> Path:
        """Write image bytes to a .dd file in output_dir."""
        path = self.output_dir / f"{name}.dd"
        path.write_bytes(data)
        return path

    def create_all_fixtures(self) -> dict[str, Path]:
        """
        Create the full suite of test fixtures on disk.
        Returns {name: path} mapping.
        """
        fixtures = {
            "zero_fill":       self.create_zero_filled_image(1),
            "ff_fill":         self.create_ff_filled_image(1),
            "random_fill":     self.create_random_filled_image(1),
            "natural_data":    self.create_natural_data_image(1),
            "mixed_50pct":     self.create_mixed_image(2, 0.5),
            "dod_pattern":     self.create_dod_pattern_image(1),
            "selective_wipe":  self.create_selective_wipe_image(4),
            "realistic":       self.create_realistic_image(4),
            "incomplete_wipe": self.create_incomplete_wipe_image(2),
        }
        paths = {}
        for name, data in fixtures.items():
            paths[name] = self.write_image(name, data)
        return paths
