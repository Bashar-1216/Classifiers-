"""
Telemetry & Prometheus-Compatible Metrics Collector.

Maintains in-memory thread-safe metrics:
- Total request counters by route and status
- Latency tracking (min, max, avg, percentiles)
- Threat detection counters by category
- Output safety modification counters
- Prometheus exposition format generator
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional


class MetricsCollector:
    """
    High-performance thread-safe telemetry and metrics engine.
    Produces Prometheus-compatible text metrics and JSON summaries.
    """

    _instance: Optional[MetricsCollector] = None
    _lock = threading.Lock()

    def __new__(cls) -> MetricsCollector:
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._init_metrics()
            return cls._instance

    def _init_metrics(self) -> None:
        self.request_count = defaultdict(int)        # key: (route, status)
        self.threat_count = defaultdict(int)         # key: category
        self.output_verdicts = defaultdict(int)      # key: verdict (ALLOW/REDACT/BLOCK)
        self.latencies: List[float] = []             # list of request durations
        self.total_requests = 0
        self.start_time = time.time()
        self._metric_lock = threading.Lock()

    def record_request(
        self,
        route: str,
        status: int,
        duration_ms: float,
        categories: Dict[str, float],
        output_verdict: str = "ALLOW",
    ) -> None:
        """Record telemetry for a completed request."""
        with self._metric_lock:
            self.total_requests += 1
            self.request_count[(route, status)] += 1
            self.output_verdicts[output_verdict] += 1
            self.latencies.append(duration_ms)
            if len(self.latencies) > 10000:
                self.latencies = self.latencies[-5000:]

            for cat, score in categories.items():
                if score >= 0.5:
                    self.threat_count[cat] += 1

    def get_summary(self) -> Dict[str, Any]:
        """Return JSON-serializable metrics summary."""
        with self._metric_lock:
            avg_latency = (
                sum(self.latencies) / len(self.latencies) if self.latencies else 0.0
            )
            p95_latency = (
                sorted(self.latencies)[int(len(self.latencies) * 0.95)]
                if self.latencies
                else 0.0
            )

            routes_summary = {
                f"{r}_{s}": count for (r, s), count in self.request_count.items()
            }

            return {
                "uptime_seconds": round(time.time() - self.start_time, 2),
                "total_requests": self.total_requests,
                "latency_ms": {
                    "avg": round(avg_latency, 2),
                    "p95": round(p95_latency, 2),
                },
                "routes": routes_summary,
                "threats_detected": dict(self.threat_count),
                "output_safety": dict(self.output_verdicts),
            }

    def generate_prometheus(self) -> str:
        """Generate Prometheus exposition format metrics string."""
        with self._metric_lock:
            lines = [
                "# HELP gateway_requests_total Total AI requests processed through gateway",
                "# TYPE gateway_requests_total counter",
            ]
            for (route, status), count in self.request_count.items():
                lines.append(
                    f'gateway_requests_total{{route="{route}",status="{status}"}} {count}'
                )

            lines.extend([
                "# HELP gateway_latency_avg_ms Average request latency in milliseconds",
                "# TYPE gateway_latency_avg_ms gauge",
            ])
            avg_lat = (
                sum(self.latencies) / len(self.latencies) if self.latencies else 0.0
            )
            lines.append(f"gateway_latency_avg_ms {avg_lat:.2f}")

            lines.extend([
                "# HELP gateway_threats_detected_total Detected security and safety threats",
                "# TYPE gateway_threats_detected_total counter",
            ])
            for cat, count in self.threat_count.items():
                lines.append(
                    f'gateway_threats_detected_total{{category="{cat}"}} {count}'
                )

            lines.extend([
                "# HELP gateway_output_safety_total Output safety filter verdicts",
                "# TYPE gateway_output_safety_total counter",
            ])
            for verdict, count in self.output_verdicts.items():
                lines.append(
                    f'gateway_output_safety_total{{verdict="{verdict}"}} {count}'
                )

            return "\n".join(lines) + "\n"
