"""Load profile for a deployed platform.

Run against a staging deployment, never production:

    CRT_LOAD_TOKEN=<pipeline or auditor token> CRT_LOAD_RUN_ID=<completed run id> \
    locust -f tests/performance/locustfile.py --host https://redteam.staging.corp.internal \
           --users 50 --spawn-rate 5 --run-time 10m --headless

The platform's read paths (run status polling by CI jobs, result pages,
decision lookups) dominate traffic; starting runs is rare and bounded by
CRT_MAX_ACTIVE_RUNS, so the mix weights polling over everything else.
"""

from __future__ import annotations

import os

from locust import HttpUser, between, task

TOKEN = os.environ.get("CRT_LOAD_TOKEN", "")
RUN_ID = os.environ.get("CRT_LOAD_RUN_ID", "")


class PipelineTraffic(HttpUser):
    wait_time = between(0.2, 1.0)

    def on_start(self) -> None:
        self.client.headers.update({"Authorization": f"Bearer {TOKEN}"})

    @task(10)
    def poll_run(self) -> None:
        self.client.get(f"/v1/runs/{RUN_ID}", name="/v1/runs/{run_id}")

    @task(4)
    def failed_results(self) -> None:
        self.client.get(
            f"/v1/runs/{RUN_ID}/results",
            params={"failed_only": "true", "limit": 100},
            name="/v1/runs/{run_id}/results",
        )

    @task(2)
    def decisions(self) -> None:
        self.client.get("/v1/gate/decisions", params={"limit": 20}, name="/v1/gate/decisions")

    @task(1)
    def suites(self) -> None:
        self.client.get("/v1/suites", name="/v1/suites")

    @task(1)
    def signing_keys(self) -> None:
        self.client.get("/.well-known/report-signing-keys", name="/.well-known/report-signing-keys")
