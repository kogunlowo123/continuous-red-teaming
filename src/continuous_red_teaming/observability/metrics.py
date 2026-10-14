"""Service metrics exposed on /metrics in Prometheus text format (own registry)."""

from __future__ import annotations

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram


class RedTeamMetrics:
    def __init__(self, registry: CollectorRegistry | None = None) -> None:
        self.registry = registry or CollectorRegistry()
        self.requests = Histogram(
            "crt_http_request_duration_seconds",
            "HTTP request latency",
            ["method", "route", "status"],
            registry=self.registry,
            buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 10),
        )
        self.probes = Counter(
            "crt_probes_total",
            "Probes executed, by category and outcome",
            ["category", "outcome"],
            registry=self.registry,
        )
        self.probe_latency = Histogram(
            "crt_probe_duration_seconds",
            "Target response time per probe",
            ["target_kind"],
            registry=self.registry,
            buckets=(0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60),
        )
        self.runs = Counter(
            "crt_runs_total", "Runs finished, by status", ["status"], registry=self.registry
        )
        self.runs_active = Gauge(
            "crt_runs_active", "Runs currently executing", registry=self.registry
        )
        self.gate_decisions = Counter(
            "crt_gate_decisions_total",
            "Release gate decisions, by outcome",
            ["outcome"],
            registry=self.registry,
        )
        self.category_failure_upper = Gauge(
            "crt_category_failure_rate_upper",
            "Wilson upper bound of the failure rate in the last gated run, per target and category",
            ["target", "category"],
            registry=self.registry,
        )
        self.access_denied = Counter(
            "crt_access_denied_total",
            "Refused requests, by action",
            ["action"],
            registry=self.registry,
        )
