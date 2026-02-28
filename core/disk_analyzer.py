"""
Disk Intelligence Layer — raw disk image I/O, cluster iteration,
slack space extraction, and unallocated region detection.

Supports: .dd, .img, .raw (plain binary) and optionally .E01 via pyewf.
Uses mmap for memory-efficient access to large images (50GB+).
"""

import mmap
import os
from pathlib import Path
from typing import Iterator

from config import config


class DiskAnalyzer:
    """
    Low-level disk image reader. Provides cluster-aligned access to raw
    disk image data without loading the entire image into memory.
    """

    def __init__(self, image_path: str, cluster_size: int | None = None):
        self.image_path = Path(image_path)
        self.cluster_size = cluster_size or config.cluster_size
        self._file = None
        self._mmap = None
        self._file_size = 0
        self._open()

    def _open(self) -> None:
        if not self.image_path.exists():
            raise FileNotFoundError(f"Disk image not found: {self.image_path}")

        ext = self.image_path.suffix.lower()
        if ext in (".e01",):
            self._open_ewf()
        else:
            self._open_raw()

    def _open_raw(self) -> None:
        self._file = open(self.image_path, "rb")
        self._file_size = os.path.getsize(self.image_path)
        if self._file_size > 0:
            self._mmap = mmap.mmap(self._file.fileno(), 0, access=mmap.ACCESS_READ)
        else:
            raise ValueError(f"Disk image is empty: {self.image_path}")

    def _open_ewf(self) -> None:
        try:
            import pyewf  # type: ignore
            self._ewf_handle = pyewf.handle()
            self._ewf_handle.open([str(self.image_path)])
            self._file_size = self._ewf_handle.get_media_size()
            self._mmap = None  # EWF uses direct reads
            self._use_ewf = True
        except ImportError:
            raise ImportError(
                "pyewf is required to read .E01 images. "
                "Install it with: pip install pyewf"
            )

    def close(self) -> None:
        if self._mmap:
            self._mmap.close()
        if self._file:
            self._file.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    # ------------------------------------------------------------------ #
    # Core accessors
    # ------------------------------------------------------------------ #

    def get_image_size(self) -> int:
        return self._file_size

    def get_cluster_count(self) -> int:
        return self._file_size // self.cluster_size

    def read_bytes(self, offset: int, length: int) -> bytes:
        """Read arbitrary bytes at a byte offset."""
        if offset < 0 or offset + length > self._file_size:
            raise ValueError(
                f"Read out of bounds: offset={offset}, length={length}, "
                f"image_size={self._file_size}"
            )
        if getattr(self, "_use_ewf", False):
            self._ewf_handle.seek(offset)
            return self._ewf_handle.read(length)
        return bytes(self._mmap[offset: offset + length])

    def read_cluster(self, cluster_id: int) -> bytes:
        """Read a single cluster by its zero-based index."""
        if cluster_id < 0 or cluster_id >= self.get_cluster_count():
            raise ValueError(
                f"Cluster {cluster_id} out of range (total: {self.get_cluster_count()})"
            )
        offset = cluster_id * self.cluster_size
        return self.read_bytes(offset, self.cluster_size)

    def iter_clusters(
        self,
        start: int = 0,
        end: int | None = None,
        step: int = 1,
    ) -> Iterator[tuple[int, bytes]]:
        """
        Yield (cluster_id, data) tuples. Respects MAX_CLUSTERS config limit.

        Args:
            start: First cluster index (inclusive).
            end:   Last cluster index (exclusive). Defaults to total clusters.
            step:  Sampling step — use >1 for quick/approximate scans.
        """
        total = self.get_cluster_count()
        end = min(end if end is not None else total, total)

        max_clusters = config.max_clusters
        yielded = 0

        for cid in range(start, end, step):
            if max_clusters and yielded >= max_clusters:
                break
            yield cid, self.read_cluster(cid)
            yielded += 1

    # ------------------------------------------------------------------ #
    # Slack space
    # ------------------------------------------------------------------ #

    def extract_slack_space(self, cluster_id: int, file_end_offset: int) -> bytes:
        """
        Return the bytes between the logical end of a file and the end of its
        cluster (slack space). This region often contains remnants of prior data.

        Args:
            cluster_id:       The cluster containing the file's last byte.
            file_end_offset:  Byte offset within the cluster where the file ends.
                              Must be in [0, cluster_size).
        """
        if file_end_offset < 0 or file_end_offset >= self.cluster_size:
            raise ValueError(
                f"file_end_offset must be in [0, {self.cluster_size}), "
                f"got {file_end_offset}"
            )
        cluster_data = self.read_cluster(cluster_id)
        return cluster_data[file_end_offset:]

    # ------------------------------------------------------------------ #
    # Unallocated regions (heuristic — no filesystem parsing)
    # ------------------------------------------------------------------ #

    def get_unallocated_regions(
        self, null_threshold: float = 0.98
    ) -> list[dict]:
        """
        Heuristically identify runs of clusters that appear unallocated by
        looking for high proportions of null bytes (a common OS behaviour
        when zeroing freed clusters) or highly uniform fill patterns.

        Returns a list of dicts:
            {"start_cluster": int, "end_cluster": int,
             "byte_count": int, "fill_byte": int | None}

        Note: For precise NTFS/FAT unallocated tracking, install pytsk3.
        """
        regions: list[dict] = []
        in_unalloc = False
        region_start = 0
        fill_byte_run = None

        for cid, data in self.iter_clusters():
            null_ratio = data.count(0) / len(data)
            is_unalloc = null_ratio >= null_threshold

            # Also flag 0xFF-flooded clusters
            if not is_unalloc:
                ff_ratio = data.count(0xFF) / len(data)
                is_unalloc = ff_ratio >= null_threshold
                fill_byte_run = 0xFF if is_unalloc else None
            else:
                fill_byte_run = 0x00

            if is_unalloc and not in_unalloc:
                region_start = cid
                in_unalloc = True
            elif not is_unalloc and in_unalloc:
                regions.append(
                    {
                        "start_cluster": region_start,
                        "end_cluster": cid - 1,
                        "byte_count": (cid - region_start) * self.cluster_size,
                        "fill_byte": fill_byte_run,
                    }
                )
                in_unalloc = False

        if in_unalloc:
            total = self.get_cluster_count()
            regions.append(
                {
                    "start_cluster": region_start,
                    "end_cluster": total - 1,
                    "byte_count": (total - region_start) * self.cluster_size,
                    "fill_byte": fill_byte_run,
                }
            )
        return regions

    # ------------------------------------------------------------------ #
    # Filesystem metadata (best-effort, no hard dependency)
    # ------------------------------------------------------------------ #

    def get_filesystem_metadata(self) -> dict:
        """
        Attempt to extract filesystem metadata (volume label, FS type,
        deleted file entries) using pytsk3 if available.

        Falls back to a minimal heuristic dict if pytsk3 is not installed.
        """
        try:
            import pytsk3  # type: ignore
            img = pytsk3.Img_Info(str(self.image_path))
            fs = pytsk3.FS_Info(img)
            meta = {
                "fs_type": str(fs.info.ftype),
                "block_size": fs.info.block_size,
                "block_count": fs.info.block_count,
                "deleted_entries": [],
            }
            for f in fs.open_dir("/"):
                if f.info and f.info.meta and f.info.meta.flags == pytsk3.TSK_FS_META_FLAG_UNALLOC:
                    meta["deleted_entries"].append(
                        {
                            "name": f.info.name.name.decode("utf-8", errors="replace"),
                            "size": f.info.meta.size,
                            "mtime": f.info.meta.mtime,
                        }
                    )
            return meta
        except ImportError:
            pass
        except Exception:
            pass

        # Minimal heuristic fallback
        return {
            "fs_type": "unknown",
            "block_size": self.cluster_size,
            "block_count": self.get_cluster_count(),
            "deleted_entries": [],
            "note": "Install pytsk3 for full filesystem metadata.",
        }

    def summary(self) -> dict:
        return {
            "image_path": str(self.image_path),
            "image_size_bytes": self._file_size,
            "image_size_mb": round(self._file_size / (1024 * 1024), 2),
            "cluster_size": self.cluster_size,
            "total_clusters": self.get_cluster_count(),
        }
