"""Unit tests for SignatureMatcher."""

import os
import pytest
from core.entropy_engine import EntropyEngine
from signatures.wipe_signatures import SignatureMatcher


@pytest.fixture
def matcher():
    return SignatureMatcher()


@pytest.fixture
def engine():
    return EntropyEngine()


class TestMatchCluster:
    def test_zero_fill_matches_sdelete_or_dd_zero(self, matcher, engine):
        data = bytes(4096)
        classification = engine.classify_region(data)
        matches = matcher.match_cluster(classification)
        tool_ids = [m["tool_id"] for m in matches[:3]]
        # Zero fill should match sdelete or dd_zero
        assert any(t in tool_ids for t in ("sdelete", "dd_zero", "manual_zero"))

    def test_random_fill_matches_dd_urandom(self, matcher, engine):
        data = os.urandom(4096)
        classification = engine.classify_region(data)
        matches = matcher.match_cluster(classification)
        assert len(matches) > 0
        # Top match should be a random-fill tool
        top_ids = [m["tool_id"] for m in matches[:2]]
        assert any(t in top_ids for t in ("dd_urandom", "dban", "shred_gnu", "eraser"))

    def test_match_returns_sorted_by_score(self, matcher, engine):
        data = os.urandom(4096)
        classification = engine.classify_region(data)
        matches = matcher.match_cluster(classification)
        scores = [m["score"] for m in matches]
        assert scores == sorted(scores, reverse=True)

    def test_natural_data_low_scores(self, matcher, engine):
        text = b"normal document content data" * 150
        classification = engine.classify_region(text[:4096])
        matches = matcher.match_cluster(classification)
        # All matches should have low scores for natural data
        if matches:
            assert matches[0]["score"] < 0.5


class TestEstimatePassCount:
    def test_pure_zero_is_one_pass(self, matcher):
        entropies = [0.0] * 100
        assert matcher.estimate_pass_count(entropies) == 1

    def test_pure_random_is_one_pass(self, matcher):
        entropies = [7.99] * 100
        # Could be 1 pass (single random) or 3 (final random pass of multi-pass)
        count = matcher.estimate_pass_count(entropies)
        assert count in (1, 3)

    def test_mixed_suggests_multipass(self, matcher):
        # Alternating between low and high entropy — multiple passes
        entropies = [0.1, 8.0, 0.1, 7.9, 8.0, 0.0, 7.8] * 5
        count = matcher.estimate_pass_count(entropies)
        assert count >= 2


class TestClassifyWipeAlgorithm:
    def test_zero_fill_image(self, matcher, engine):
        clusters = [bytes(4096)] * 20
        analyses = [engine.classify_region(c) for c in clusters]
        result = matcher.classify_wipe_algorithm(analyses)
        assert result["tool"] != "Unknown"
        assert result["confidence"] > 0.1

    def test_random_fill_image(self, matcher, engine):
        clusters = [os.urandom(4096) for _ in range(20)]
        analyses = [engine.classify_region(c) for c in clusters]
        result = matcher.classify_wipe_algorithm(analyses)
        assert result["tool"] != "Unknown"
        assert result["confidence"] > 0.2
        assert result["pass_count"] >= 1

    def test_returns_all_expected_keys(self, matcher, engine):
        clusters = [os.urandom(4096) for _ in range(5)]
        analyses = [engine.classify_region(c) for c in clusters]
        result = matcher.classify_wipe_algorithm(analyses)
        for key in ("tool", "tool_id", "algorithm", "pass_count", "confidence", "evidence"):
            assert key in result


class TestDetectIncompleteWipe:
    def test_fully_wiped_no_incomplete(self, matcher, engine):
        clusters = [os.urandom(4096) for _ in range(20)]
        analyses = [engine.classify_region(c) for c in clusters]
        result = matcher.detect_incomplete_wipe(analyses)
        assert not result["has_incomplete_wipe"]

    def test_half_wiped_is_incomplete(self, matcher, engine):
        wiped = [engine.classify_region(os.urandom(4096)) for _ in range(10)]
        natural_text = b"normal content file data"
        intact = [engine.classify_region((natural_text * 200)[:4096]) for _ in range(10)]
        analyses = wiped + intact
        result = matcher.detect_incomplete_wipe(analyses)
        assert result["has_incomplete_wipe"]
        assert result["intact_fraction"] > 0.3
