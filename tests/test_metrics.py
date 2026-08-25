"""
Tests for Observability and Metrics System.
"""

import pytest

from gateway.metrics import MetricsCollector
from gateway.observability import AuditLogger


class TestObservabilityMetrics:
    """Test suite for metrics collection and audit logging."""

    @pytest.fixture(autouse=True)
    def reset_metrics(self):
        collector = MetricsCollector()
        collector._init_metrics()
        return collector

    def test_prompt_hashing(self):
        h1 = AuditLogger.hash_text("Explain how photosynthesis works")
        h2 = AuditLogger.hash_text("Explain how photosynthesis works")
        h3 = AuditLogger.hash_text("Different prompt")
        assert h1 == h2
        assert h1 != h3
        assert len(h1) == 16

    def test_metrics_recording_and_summary(self, reset_metrics):
        collector = reset_metrics
        collector.record_request(
            route="NORMAL",
            status=200,
            duration_ms=45.2,
            categories={"security": 0.1, "privacy": 0.0},
            output_verdict="ALLOW",
        )
        collector.record_request(
            route="SHIELD",
            status=200,
            duration_ms=88.5,
            categories={"security": 0.95, "jailbreak": 0.92},
            output_verdict="REDACT",
        )

        summary = collector.get_summary()
        assert summary["total_requests"] == 2
        assert "NORMAL_200" in summary["routes"]
        assert "SHIELD_200" in summary["routes"]
        assert summary["threats_detected"].get("security") == 1
        assert summary["threats_detected"].get("jailbreak") == 1
        assert summary["output_safety"].get("ALLOW") == 1
        assert summary["output_safety"].get("REDACT") == 1

    def test_prometheus_exposition_generation(self, reset_metrics):
        collector = reset_metrics
        collector.record_request(
            route="NORMAL",
            status=200,
            duration_ms=50.0,
            categories={"privacy": 0.90},
            output_verdict="ALLOW",
        )

        prom_text = collector.generate_prometheus()
        assert "gateway_requests_total" in prom_text
        assert 'route="NORMAL"' in prom_text
        assert "gateway_latency_avg_ms" in prom_text
        assert "gateway_threats_detected_total" in prom_text
        assert "gateway_output_safety_total" in prom_text
