#!/usr/bin/env python3
"""Tests for the EDAMAME Score Calculator.

Tests the scoring algorithm against known expectations,
verifying consistency with the Rust implementation in edamame_foundation.
"""

import json
import os
import tempfile
import unittest
from unittest.mock import patch

from score_calculator import (
    DIMENSIONS,
    VALID_PLATFORMS,
    ComplianceResult,
    DimensionScore,
    MetricResult,
    ScoreResult,
    compute_score,
    fetch_threat_model,
    format_json_report,
    format_text_report,
    load_checks_file,
    load_threat_model,
    main,
)


def make_threat_model(metrics: list[dict], name: str = "test model") -> dict:
    """Helper to build a minimal threat model dict."""
    return {
        "name": name,
        "extends": "none",
        "date": "January 1st 2025",
        "signature": "test",
        "metrics": metrics,
    }


def make_metric(
    name: str,
    dimension: str = "network",
    severity: int = 3,
    tags: list[str] | None = None,
) -> dict:
    """Helper to build a minimal metric dict."""
    return {
        "name": name,
        "metrictype": "bool",
        "dimension": dimension,
        "severity": severity,
        "scope": "generic",
        "tags": tags or [],
        "description": [{"locale": "EN", "title": name, "summary": ""}],
        "implementation": {},
        "remediation": {},
        "rollback": {},
    }


class TestComputeScoreBasic(unittest.TestCase):
    """Test fundamental score computation."""

    def test_empty_model(self):
        """Empty threat model should yield zero scores."""
        model = make_threat_model([])
        result = compute_score(model)
        self.assertEqual(result.overall, 0)
        self.assertEqual(result.stars, 0.0)
        self.assertEqual(result.total_metrics, 0)
        self.assertEqual(result.active_threats, 0)
        self.assertEqual(result.inactive_threats, 0)
        # All dimensions should be -1 (no metrics)
        for dim in DIMENSIONS:
            self.assertEqual(result.dimensions[dim].score, -1)

    def test_all_active_worst_case(self):
        """All threats active = worst score (0)."""
        model = make_threat_model([
            make_metric("threat1", "network", 5),
            make_metric("threat2", "network", 3),
        ])
        result = compute_score(model)
        self.assertEqual(result.dimensions["network"].score, 0)
        self.assertEqual(result.overall, 0)
        self.assertEqual(result.stars, 0.0)
        self.assertEqual(result.active_threats, 2)
        self.assertEqual(result.inactive_threats, 0)

    def test_all_inactive_best_case(self):
        """All threats inactive = best score (100%)."""
        model = make_threat_model([
            make_metric("threat1", "network", 5),
            make_metric("threat2", "network", 3),
        ])
        result = compute_score(model, all_inactive=True)
        self.assertEqual(result.dimensions["network"].score, 100)
        self.assertEqual(result.overall, 100)
        self.assertEqual(result.stars, 5.0)
        self.assertEqual(result.active_threats, 0)
        self.assertEqual(result.inactive_threats, 2)

    def test_partial_inactive(self):
        """Partial remediation should give proportional score weighted by severity."""
        model = make_threat_model([
            make_metric("high_sev", "network", 5),
            make_metric("low_sev", "network", 1),
        ])
        # Only remediate the low severity threat
        result = compute_score(model, inactive_threats={"low_sev"})
        # network: current=1, max=6, score=100*1//6=16
        self.assertEqual(result.dimensions["network"].current, 1)
        self.assertEqual(result.dimensions["network"].maximum, 6)
        self.assertEqual(result.dimensions["network"].score, 16)
        self.assertEqual(result.active_threats, 1)
        self.assertEqual(result.inactive_threats, 1)

        # Remediate the high severity threat instead
        result2 = compute_score(model, inactive_threats={"high_sev"})
        # network: current=5, max=6, score=100*5//6=83
        self.assertEqual(result2.dimensions["network"].current, 5)
        self.assertEqual(result2.dimensions["network"].maximum, 6)
        self.assertEqual(result2.dimensions["network"].score, 83)


class TestComputeScoreDimensions(unittest.TestCase):
    """Test dimension-level scoring."""

    def test_multiple_dimensions(self):
        """Metrics in different dimensions are scored independently."""
        model = make_threat_model([
            make_metric("net1", "network", 4),
            make_metric("cred1", "credentials", 2),
            make_metric("app1", "applications", 3),
        ])
        result = compute_score(model, inactive_threats={"net1", "app1"})
        self.assertEqual(result.dimensions["network"].score, 100)
        self.assertEqual(result.dimensions["credentials"].score, 0)
        self.assertEqual(result.dimensions["applications"].score, 100)
        # system services and system integrity have no metrics
        self.assertEqual(result.dimensions["system services"].score, -1)
        self.assertEqual(result.dimensions["system integrity"].score, -1)
        # overall: current=4+0+3=7, max=4+2+3=9, score=100*7//9=77
        self.assertEqual(result.overall, 77)

    def test_all_five_dimensions(self):
        """All five dimensions with metrics."""
        model = make_threat_model([
            make_metric("net1", "network", 2),
            make_metric("ss1", "system services", 3),
            make_metric("si1", "system integrity", 4),
            make_metric("cred1", "credentials", 1),
            make_metric("app1", "applications", 5),
        ])
        result = compute_score(model, all_inactive=True)
        for dim in DIMENSIONS:
            self.assertNotEqual(result.dimensions[dim].score, -1)
            self.assertEqual(result.dimensions[dim].score, 100)
        self.assertEqual(result.overall, 100)
        self.assertEqual(result.stars, 5.0)


class TestComputeScoreStars(unittest.TestCase):
    """Test star rating computation."""

    def test_stars_linear_scaling(self):
        """Stars = overall * 5.0 / 100.0."""
        # Build a model where we can control the exact outcome
        model = make_threat_model([
            make_metric("t1", "network", 1),
            make_metric("t2", "network", 1),
            make_metric("t3", "network", 1),
            make_metric("t4", "network", 1),
            make_metric("t5", "network", 1),
        ])
        # 3 out of 5 inactive => overall=60%, stars=3.0
        result = compute_score(model, inactive_threats={"t1", "t2", "t3"})
        self.assertEqual(result.overall, 60)
        self.assertAlmostEqual(result.stars, 3.0)

    def test_stars_zero(self):
        """All active = 0 stars."""
        model = make_threat_model([make_metric("t1", "network", 5)])
        result = compute_score(model)
        self.assertEqual(result.stars, 0.0)

    def test_stars_five(self):
        """All inactive = 5 stars."""
        model = make_threat_model([make_metric("t1", "network", 5)])
        result = compute_score(model, all_inactive=True)
        self.assertEqual(result.stars, 5.0)


class TestComputeCompliance(unittest.TestCase):
    """Test compliance computation."""

    def test_no_tags_no_compliance(self):
        """Metrics without tags produce no compliance entries."""
        model = make_threat_model([make_metric("t1", "network", 3)])
        result = compute_score(model, all_inactive=True)
        self.assertEqual(len(result.compliance), 0)

    def test_single_tag_all_compliant(self):
        """All metrics with a tag inactive = 100% compliance."""
        model = make_threat_model([
            make_metric("t1", "network", 3, tags=["CIS Benchmark Level 1,Something"]),
            make_metric("t2", "network", 2, tags=["CIS Benchmark Level 1,Other"]),
        ])
        result = compute_score(model, all_inactive=True)
        self.assertIn("CIS Benchmark Level 1", result.compliance)
        self.assertEqual(result.compliance["CIS Benchmark Level 1"].percentage, 100.0)

    def test_single_tag_partial_compliant(self):
        """Partial compliance."""
        model = make_threat_model([
            make_metric("t1", "network", 3, tags=["CIS Benchmark Level 1,A"]),
            make_metric("t2", "network", 2, tags=["CIS Benchmark Level 1,B"]),
        ])
        result = compute_score(model, inactive_threats={"t1"})
        c = result.compliance["CIS Benchmark Level 1"]
        self.assertEqual(c.compliant, 1)
        self.assertEqual(c.total, 2)
        self.assertEqual(c.percentage, 50.0)

    def test_multiple_tags(self):
        """Metric with multiple tags counts toward each tag's compliance."""
        model = make_threat_model([
            make_metric("t1", "network", 3, tags=["CIS,A", "ISO 27001/2,B"]),
        ])
        result = compute_score(model, all_inactive=True)
        self.assertIn("CIS", result.compliance)
        self.assertIn("ISO 27001/2", result.compliance)
        self.assertEqual(result.compliance["CIS"].percentage, 100.0)
        self.assertEqual(result.compliance["ISO 27001/2"].percentage, 100.0)

    def test_tag_without_comma(self):
        """Tags without comma use the whole string as the prefix."""
        model = make_threat_model([
            make_metric("t1", "network", 3, tags=["Personal Posture"]),
        ])
        result = compute_score(model, all_inactive=True)
        self.assertIn("Personal Posture", result.compliance)


class TestComputeScoreIntegerDivision(unittest.TestCase):
    """Test that integer division matches the Rust implementation."""

    def test_integer_division(self):
        """Score uses integer division (floor), matching Rust behavior."""
        # severity 3 out of 7 = 42.8... => floors to 42
        model = make_threat_model([
            make_metric("t1", "network", 3),
            make_metric("t2", "network", 4),
        ])
        result = compute_score(model, inactive_threats={"t1"})
        # 100 * 3 // 7 = 42
        self.assertEqual(result.dimensions["network"].score, 42)
        self.assertEqual(result.overall, 42)


class TestLoadChecksFile(unittest.TestCase):
    """Test checks file loading."""

    def test_list_format(self):
        """Load a simple JSON list."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(["threat1", "threat2"], f)
            f.flush()
            result = load_checks_file(f.name)
        os.unlink(f.name)
        self.assertEqual(result, {"threat1", "threat2"})

    def test_object_format(self):
        """Load a JSON object with 'inactive' key."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"inactive": ["t1", "t2"]}, f)
            f.flush()
            result = load_checks_file(f.name)
        os.unlink(f.name)
        self.assertEqual(result, {"t1", "t2"})

    def test_invalid_format(self):
        """Invalid format raises ValueError."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"wrong_key": []}, f)
            f.flush()
            with self.assertRaises(ValueError):
                load_checks_file(f.name)
        os.unlink(f.name)


class TestLocalFileLoading(unittest.TestCase):
    """Test local threat model file loading."""

    def test_load_local_file(self):
        """Load a threat model from a local JSON file."""
        model = make_threat_model([make_metric("t1", "network", 3)])
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(model, f)
            f.flush()
            loaded = load_threat_model(f.name)
        os.unlink(f.name)
        self.assertEqual(loaded["name"], "test model")
        self.assertEqual(len(loaded["metrics"]), 1)

    def test_file_not_found(self):
        """Missing file raises FileNotFoundError."""
        with self.assertRaises(FileNotFoundError):
            load_threat_model("/nonexistent/file.json")


class TestOutputFormatting(unittest.TestCase):
    """Test text and JSON output formatting."""

    def _make_result(self) -> ScoreResult:
        model = make_threat_model([
            make_metric("firewall off", "network", 4, tags=["CIS,Enable Firewall"]),
            make_metric("weak pw", "credentials", 2),
        ])
        return compute_score(model, inactive_threats={"firewall off"})

    def test_text_report_contains_stars(self):
        result = self._make_result()
        report = format_text_report(result)
        self.assertIn("Stars:", report)
        self.assertIn("Overall:", report)
        self.assertIn("Dimension Scores", report)

    def test_text_report_contains_threats(self):
        result = self._make_result()
        report = format_text_report(result)
        self.assertIn("firewall off", report)
        self.assertIn("weak pw", report)
        self.assertIn("OK", report)
        self.assertIn("ACTIVE", report)

    def test_json_report_is_valid_json(self):
        result = self._make_result()
        report = format_json_report(result)
        data = json.loads(report)
        self.assertIn("stars", data)
        self.assertIn("overall_percent", data)
        self.assertIn("dimensions", data)
        self.assertIn("metrics", data)

    def test_json_report_values(self):
        result = self._make_result()
        data = json.loads(format_json_report(result))
        # network: 4/4=100%, credentials: 0/2=0%, overall: 4/6=66%
        self.assertEqual(data["dimensions"]["network"]["score_percent"], 100)
        self.assertEqual(data["dimensions"]["credentials"]["score_percent"], 0)
        self.assertEqual(data["overall_percent"], 66)


class TestCLI(unittest.TestCase):
    """Test CLI argument handling."""

    def test_list_threats(self):
        """--list-threats should succeed with local file."""
        model = make_threat_model([make_metric("test_threat", "network", 3)])
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(model, f)
            f.flush()
            ret = main([
                "--platform", "macOS",
                "--local-file", f.name,
                "--list-threats",
            ])
        os.unlink(f.name)
        self.assertEqual(ret, 0)

    def test_json_output(self):
        """--json should produce valid JSON."""
        model = make_threat_model([make_metric("t1", "network", 3)])
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(model, f)
            f.flush()
            ret = main([
                "--platform", "macOS",
                "--local-file", f.name,
                "--all-inactive",
                "--json",
            ])
        os.unlink(f.name)
        self.assertEqual(ret, 0)


class TestFetchThreatModel(unittest.TestCase):
    """Test remote fetching (may require network)."""

    def test_invalid_platform(self):
        """Invalid platform raises ValueError."""
        with self.assertRaises(ValueError):
            fetch_threat_model("InvalidOS")


class TestWithRealModel(unittest.TestCase):
    """Integration tests using real threat model files if available locally."""

    THREAT_MODEL_PATH = os.path.join(
        os.path.dirname(__file__), "..", "threatmodels", "threatmodel-macOS.json"
    )

    @unittest.skipUnless(
        os.path.exists(THREAT_MODEL_PATH),
        "Local threatmodels repo not available",
    )
    def test_real_model_all_inactive(self):
        """Real macOS model, all inactive should give 5.0 stars."""
        model = load_threat_model(self.THREAT_MODEL_PATH)
        result = compute_score(model, all_inactive=True)
        self.assertEqual(result.stars, 5.0)
        self.assertEqual(result.overall, 100)
        self.assertEqual(result.active_threats, 0)

    @unittest.skipUnless(
        os.path.exists(THREAT_MODEL_PATH),
        "Local threatmodels repo not available",
    )
    def test_real_model_all_active(self):
        """Real macOS model, all active should give 0.0 stars."""
        model = load_threat_model(self.THREAT_MODEL_PATH)
        result = compute_score(model)
        self.assertEqual(result.stars, 0.0)
        self.assertEqual(result.overall, 0)
        self.assertEqual(result.inactive_threats, 0)

    @unittest.skipUnless(
        os.path.exists(THREAT_MODEL_PATH),
        "Local threatmodels repo not available",
    )
    def test_real_model_has_compliance_tags(self):
        """Real macOS model should have compliance tags."""
        model = load_threat_model(self.THREAT_MODEL_PATH)
        result = compute_score(model, all_inactive=True)
        self.assertGreater(len(result.compliance), 0)
        self.assertIn("CIS Benchmark Level 1", result.compliance)


if __name__ == "__main__":
    unittest.main()
