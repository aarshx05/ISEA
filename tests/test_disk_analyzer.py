"""Unit tests for DiskAnalyzer."""

import os
import tempfile
from pathlib import Path

import pytest
from core.disk_analyzer import DiskAnalyzer
from tests.synthetic_generator import SyntheticDiskFactory


@pytest.fixture
def temp_image(tmp_path):
    """Create a small 64KB test image."""
    data = os.urandom(64 * 1024)
    img_path = tmp_path / "test.dd"
    img_path.write_bytes(data)
    return str(img_path)


@pytest.fixture
def zero_image(tmp_path):
    """Create a 64KB zero-filled image."""
    data = bytes(64 * 1024)
    img_path = tmp_path / "zero.dd"
    img_path.write_bytes(data)
    return str(img_path)


class TestDiskAnalyzerBasics:
    def test_opens_raw_image(self, temp_image):
        with DiskAnalyzer(temp_image, cluster_size=512) as disk:
            assert disk.get_image_size() == 64 * 1024

    def test_cluster_count(self, temp_image):
        with DiskAnalyzer(temp_image, cluster_size=512) as disk:
            assert disk.get_cluster_count() == 128  # 64KB / 512

    def test_read_cluster_returns_correct_size(self, temp_image):
        with DiskAnalyzer(temp_image, cluster_size=512) as disk:
            data = disk.read_cluster(0)
            assert len(data) == 512

    def test_read_cluster_out_of_bounds(self, temp_image):
        with DiskAnalyzer(temp_image, cluster_size=512) as disk:
            with pytest.raises(ValueError):
                disk.read_cluster(9999)

    def test_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            DiskAnalyzer("/nonexistent/path/image.dd")


class TestClusterIteration:
    def test_iter_yields_all_clusters(self, temp_image):
        with DiskAnalyzer(temp_image, cluster_size=512) as disk:
            clusters = list(disk.iter_clusters())
            assert len(clusters) == 128

    def test_iter_respects_range(self, temp_image):
        with DiskAnalyzer(temp_image, cluster_size=512) as disk:
            clusters = list(disk.iter_clusters(start=10, end=20))
            assert len(clusters) == 10

    def test_iter_step(self, temp_image):
        with DiskAnalyzer(temp_image, cluster_size=512) as disk:
            clusters = list(disk.iter_clusters(step=2))
            assert len(clusters) == 64  # every other cluster


class TestSlackSpace:
    def test_slack_space_correct_length(self, temp_image):
        with DiskAnalyzer(temp_image, cluster_size=512) as disk:
            slack = disk.extract_slack_space(0, file_end_offset=200)
            assert len(slack) == 312  # 512 - 200

    def test_slack_space_invalid_offset(self, temp_image):
        with DiskAnalyzer(temp_image, cluster_size=512) as disk:
            with pytest.raises(ValueError):
                disk.extract_slack_space(0, file_end_offset=600)  # > cluster_size


class TestUnallocatedRegions:
    def test_zero_image_detected_as_unallocated(self, zero_image):
        with DiskAnalyzer(zero_image, cluster_size=512) as disk:
            regions = disk.get_unallocated_regions()
            assert len(regions) >= 1
            # Should detect most of the image as unallocated
            total_bytes = sum(r["byte_count"] for r in regions)
            assert total_bytes > 0

    def test_random_image_not_fully_unallocated(self):
        import tempfile
        data = os.urandom(64 * 1024)
        with tempfile.NamedTemporaryFile(suffix=".dd", delete=False) as f:
            f.write(data)
            path = f.name
        try:
            with DiskAnalyzer(path, cluster_size=512) as disk:
                regions = disk.get_unallocated_regions()
                total_bytes = sum(r["byte_count"] for r in regions)
                # Random data should not be flagged as unallocated
                assert total_bytes < 64 * 1024 * 0.5
        finally:
            os.unlink(path)


class TestSummary:
    def test_summary_fields(self, temp_image):
        with DiskAnalyzer(temp_image, cluster_size=512) as disk:
            s = disk.summary()
            assert "image_size_bytes" in s
            assert "total_clusters" in s
            assert s["cluster_size"] == 512
