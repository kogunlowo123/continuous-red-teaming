"""Release-gate client used by the composite GitHub Action (``action.yml``).

Standard library only, so the action runs on any runner with Python 3.10+
without installing anything:

1. authenticate with an explicit token or a GitHub Actions OIDC token;
2. start a validation run and poll it to completion;
3. evaluate the release gate and verify the signed report server-side;
4. optionally wait for a human approval;
5. write step outputs, a job summary and the signed report file.

Exit codes: 0 releasable (pass / approved), 1 not releasable, 2 operational error.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

TERMINAL_RUN_STATES = {"completed", "aborted", "failed"}
RELEASABLE = {"pass", "approved"}


class GateClientError(Exception):
    """Operational failure: the gate could not be evaluated."""


Transport = Callable[[str, str, dict[str, str], bytes | None], tuple[int, bytes]]


def urllib_transport(
    method: str, url: str, headers: dict[str, str], body: bytes | None
) -> tuple[int, bytes]:
    if not url.startswith(("https://", "http://")):
        raise GateClientError(f"unsupported URL {url!r}")
    request = urllib.request.Request(url, data=body, method=method, headers=headers)  # noqa: S310
    try:
        with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310  # nosec B310
            return int(response.status), response.read()
    except urllib.error.HTTPError as exc:
        return int(exc.code), exc.read()
    except (urllib.error.URLError, TimeoutError) as exc:
        raise GateClientError(f"cannot reach {url}: {exc}") from exc


@dataclass
class GateApi:
    base_url: str
    token: str
    transport: Transport = urllib_transport

    def call(self, method: str, path: str, payload: dict[str, Any] | None = None) -> Any:
        body = None if payload is None else json.dumps(payload).encode()
        headers = {"Authorization": f"Bearer {self.token}", "Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        status, raw = self.transport(method, self.base_url.rstrip("/") + path, headers, body)
        try:
            document = json.loads(raw.decode() or "null")
        except ValueError as exc:
            raise GateClientError(f"{method} {path}: HTTP {status}, body is not JSON") from exc
        if status >= 400:
            detail = document.get("error_description") if isinstance(document, dict) else None
            raise GateClientError(f"{method} {path}: HTTP {status}: {detail or document}")
        return document


def github_oidc_token(audience: str, transport: Transport = urllib_transport) -> str:
    url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL")
    bearer = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if not url or not bearer:
        raise GateClientError(
            "no token given and GitHub OIDC is unavailable (add 'id-token: write' permission)"
        )
    separator = "&" if "?" in url else "?"
    full = f"{url}{separator}audience={urllib.parse.quote(audience, safe='')}"
    status, raw = transport("GET", full, {"Authorization": f"Bearer {bearer}"}, None)
    if status != 200:
        raise GateClientError(f"GitHub OIDC token request failed with HTTP {status}")
    value = json.loads(raw.decode()).get("value")
    if not isinstance(value, str) or not value:
        raise GateClientError("GitHub OIDC response carried no token")
    return value


@dataclass
class Options:
    url: str
    target_id: str
    target_version: str
    suite: str
    environment: str = "staging"
    seed: int | None = None
    poll_interval_s: float = 5.0
    timeout_s: float = 1800.0
    approval_wait_s: float = 0.0
    report_file: Path | None = None
    summary_file: Path | None = None
    output_file: Path | None = None
    sleep: Callable[[float], None] = time.sleep
    clock: Callable[[], float] = time.monotonic
    log: Callable[[str], None] = field(default=lambda m: print(m, flush=True))


def _wait_for_run(api: GateApi, run_id: str, options: Options) -> dict[str, Any]:
    deadline = options.clock() + options.timeout_s
    while True:
        run: dict[str, Any] = api.call("GET", f"/v1/runs/{run_id}")
        if run["status"] in TERMINAL_RUN_STATES:
            return run
        if options.clock() > deadline:
            raise GateClientError(f"run {run_id} did not finish within {options.timeout_s:g}s")
        options.sleep(options.poll_interval_s)


def _wait_for_approval(api: GateApi, decision: dict[str, Any], options: Options) -> dict[str, Any]:
    deadline = options.clock() + options.approval_wait_s
    while decision["outcome"] == "require_approval" and options.clock() < deadline:
        options.log("release requires human approval; waiting")
        options.sleep(options.poll_interval_s)
        decision = api.call("GET", f"/v1/gate/decisions/{decision['id']}")
    return decision


def summary_markdown(decision: dict[str, Any], run: dict[str, Any]) -> str:
    report = decision["signed_report"]["report"]
    lines = [
        f"## Release gate: `{decision['outcome']}`",
        "",
        f"Target `{report['target_name']}` version `{report['target_version']}`, "
        f"suite `{report['suite_name']}@{report['suite_version']}`, seed `{run['seed']}`.",
        "",
        "| Category | Verdict | Failures / conclusive | Upper bound | Threshold |",
        "|---|---|---|---|---|",
    ]
    stats = {c["category"]: c for c in report["summary"]["categories"]}
    for item in report["assessments"]:
        cat = stats.get(item["category"], {})
        lines.append(
            f"| {item['category']} | {item['verdict']} | "
            f"{cat.get('failures', 0)} / {item['conclusive']} | "
            f"{item['upper_bound']:.4f} | {item['max_failure_rate']:.4f} |"
        )
    lines += [
        "",
        f"Policy rules: {', '.join(report['matched_rules']) or 'none'} "
        f"({report['decision_reason']}).",
        f"Report digest `{decision['signed_report']['signature']['digest']}`, "
        f"key `{decision['signed_report']['signature']['key_id']}`.",
        "",
    ]
    return "\n".join(lines)


def run_gate(api: GateApi, options: Options) -> int:
    request: dict[str, Any] = {
        "target_id": options.target_id,
        "target_version": options.target_version,
        "suite": options.suite,
        "environment": options.environment,
    }
    if options.seed is not None:
        request["seed"] = options.seed
    run = api.call("POST", "/v1/runs", request)
    options.log(f"run {run['id']} queued ({run['probe_count']} probes, seed {run['seed']})")
    run = _wait_for_run(api, run["id"], options)
    if run["status"] != "completed":
        raise GateClientError(f"run {run['id']} ended {run['status']}: {run.get('error')}")
    decision = api.call("POST", f"/v1/runs/{run['id']}/gate")
    verification = api.call("POST", "/v1/reports/verify", decision["signed_report"])
    if not verification.get("valid"):
        raise GateClientError(f"report signature invalid: {verification.get('reason')}")
    if options.approval_wait_s > 0:
        decision = _wait_for_approval(api, decision, options)
    outcome = str(decision["outcome"])
    options.log(f"gate decision {decision['id']}: {outcome}")
    if options.report_file is not None:
        options.report_file.write_text(json.dumps(decision["signed_report"], indent=2), "utf-8")
    if options.summary_file is not None:
        with options.summary_file.open("a", encoding="utf-8") as handle:
            handle.write(summary_markdown(decision, run))
    if options.output_file is not None:
        with options.output_file.open("a", encoding="utf-8") as handle:
            handle.write(f"run-id={run['id']}\n")
            handle.write(f"decision-id={decision['id']}\n")
            handle.write(f"outcome={outcome}\n")
            handle.write(f"report-digest={decision['signed_report']['signature']['digest']}\n")
    return 0 if outcome in RELEASABLE else 1


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate the continuous red-teaming gate")
    parser.add_argument("--url", required=True)
    parser.add_argument("--target-id", required=True)
    parser.add_argument("--target-version", required=True)
    parser.add_argument("--suite", required=True)
    parser.add_argument("--environment", default="staging")
    parser.add_argument("--seed", type=int)
    parser.add_argument("--audience", default="continuous-red-teaming")
    parser.add_argument("--poll-interval", type=float, default=5.0)
    parser.add_argument("--timeout-minutes", type=float, default=30.0)
    parser.add_argument("--approval-wait-minutes", type=float, default=0.0)
    parser.add_argument("--report-file", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None, transport: Transport = urllib_transport) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        token = os.environ.get("CRT_GATE_TOKEN") or github_oidc_token(args.audience, transport)
        options = Options(
            url=args.url,
            target_id=args.target_id,
            target_version=args.target_version,
            suite=args.suite,
            environment=args.environment,
            seed=args.seed,
            poll_interval_s=args.poll_interval,
            timeout_s=args.timeout_minutes * 60,
            approval_wait_s=args.approval_wait_minutes * 60,
            report_file=args.report_file,
            summary_file=_env_path("GITHUB_STEP_SUMMARY"),
            output_file=_env_path("GITHUB_OUTPUT"),
        )
        return run_gate(GateApi(args.url, token, transport), options)
    except GateClientError as exc:
        print(f"::error::release gate could not be evaluated: {exc}", file=sys.stderr)
        return 2


def _env_path(name: str) -> Path | None:
    value = os.environ.get(name)
    return Path(value) if value else None


if __name__ == "__main__":
    raise SystemExit(main())
