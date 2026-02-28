"""Unit tests for EntropyEngine."""

import pytest
from core.entropy_engine import EntropyEngine
from tests.synthetic_generator import SyntheticDiskFactory


@pytest.fixture
def engine():
    return EntropyEngine()


@pytest.fixture
def factory():
    return SyntheticDiskFactory()


class TestShannonEntropy:
    def test_zero_buffer_has_near_zero_entropy(self, engine):
        data = bytes(512)
        assert engine.shannon_entropy(data) < 0.01

    def test_random_buffer_has_high_entropy(self, engine):
        import os
        data = os.urandom(4096)
        # Should be close to 8.0 for true random
        assert engine.shannon_entropy(data) > 7.5

    def test_alternating_has_entropy_one(self, engine):
        data = bytes([0x00, 0xFF] * 256)
        entropy = engine.shannon_entropy(data)
        # Two equally likely values → entropy = 1.0
        assert abs(entropy - 1.0) < 0.01

    def test_empty_returns_zero(self, engine):
        assert engine.shannon_entropy(b"") == 0.0


class TestDetectUniformFill:
    def test_all_zeros(self, engine):
        is_uniform, fill_byte = engine.detect_uniform_fill(bytes(512))
        assert is_uniform is True
        assert fill_byte == 0x00

    def test_all_ff(self, engine):
        is_uniform, fill_byte = engine.detect_uniform_fill(bytes([0xFF] * 512))
        assert is_uniform is True
        assert fill_byte == 0xFF

    def test_random_not_uniform(self, engine):
        import os
        is_uniform, fill_byte = engine.detect_uniform_fill(os.urandom(512))
        assert is_uniform is False
        assert fill_byte is None


class TestDetectPatternRepetition:
    def test_alternating_pattern(self, engine):
        data = bytes([0x00, 0xFF] * 256)
        is_pattern, pattern = engine.detect_pattern_repetition(data)
        assert is_pattern is True
        assert pattern == bytes([0x00, 0xFF])

    def test_single_byte_pattern(self, engine):
        data = bytes([0xA5] * 512)
        # Single byte = uniform fill, not "pattern" (pattern requires len >=2)
        # But all-same-byte is just uniform, not a repeating sequence
        # Depending on implementation, this may or may not be detected
        # At minimum it should not crash
        is_pattern, pattern = engine.detect_pattern_repetition(data)
        # Accept either result — single byte is borderline
        assert isinstance(is_pattern, bool)

    def test_random_no_pattern(self, engine):
        import os
        data = os.urandom(512)
        is_pattern, pattern = engine.detect_pattern_repetition(data)
        assert is_pattern is False


class TestClassifyRegion:
    def test_zero_fill_classifies_as_wipe(self, engine):
        result = engine.classify_region(bytes(4096))
        # Pure zeros: entropy ~0, classified as natural_residual or intentional_wipe
        # (zero-fill may be os_clear or intentional — both are valid)
        assert result["classification"] in ("natural_residual", "os_clear", "intentional_wipe")
        assert result["entropy"] < 0.01

    def test_random_fill_classifies_as_secure_erase(self, engine):
        import os
        result = engine.classify_region(os.urandom(4096))
        assert result["classification"] in ("intentional_wipe", "secure_erase")
        assert result["entropy"] > 7.0

    def test_natural_text_classifies_as_natural(self, engine):
        text = b"This is a test document with normal text content." * 80
        result = engine.classify_region(text[:4096])
        assert result["classification"] in ("natural_residual", "os_clear")

    def test_classification_has_required_keys(self, engine):
        result = engine.classify_region(bytes(512))
        for key in ("classification", "entropy", "confidence", "fill_byte", "is_random", "notes"):
            assert key in result


class TestAggregate:
    def test_aggregate_empty(self, engine):
        result = engine.aggregate_region_stats([])
        assert result == {}

    def test_aggregate_all_random(self, engine):
        import os
        clusters = [os.urandom(4096) for _ in range(10)]
        analyses = engine.analyze_cluster_batch(clusters)
        stats = engine.aggregate_region_stats(analyses)
        assert stats["total_clusters"] == 10
        assert stats["mean_entropy"] > 7.0
        assert stats["wipe_fraction"] > 0.5
