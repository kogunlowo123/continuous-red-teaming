"""Export published contracts: JSON Schemas for inputs/outputs and the OpenAPI document.

python -m continuous_red_teaming.contracts            # rewrite schemas/ and docs/api/
python -m continuous_red_teaming.contracts --check    # exit 1 if committed files are stale
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel

from continuous_red_teaming.adapters.base import AgentReply
from continuous_red_teaming.api.app import create_app
from continuous_red_teaming.application.service import RunRequest
from continuous_red_teaming.domain.models import (
    GateDecision,
    ProbeInvocation,
    Run,
    SignedReport,
    TargetRegistration,
)
from continuous_red_teaming.domain.suites import Suite
from continuous_red_teaming.gate.policy import GatePolicy

MODELS: dict[str, type[BaseModel]] = {
    "suite": Suite,
    "release-gate.policy": GatePolicy,
    "target-registration.request": TargetRegistration,
    "run.request": RunRequest,
    "run.response": Run,
    "gate-decision.response": GateDecision,
    "signed-report": SignedReport,
    "agent-invocation.request": ProbeInvocation,
    "agent-reply.response": AgentReply,
}


async def _no_container() -> Any:  # pragma: no cover - never started
    raise RuntimeError("contract export does not start the application")


def documents() -> dict[str, dict[str, Any]]:
    docs: dict[str, dict[str, Any]] = {
        f"schemas/{name}.schema.json": {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": (
                "https://github.com/kogunlowo123/continuous-red-teaming/"
                f"schemas/{name}.schema.json"
            ),
            **model.model_json_schema(mode="validation"),
        }
        for name, model in MODELS.items()
    }
    app: FastAPI = create_app(_no_container)
    docs["docs/api/openapi.json"] = app.openapi()
    return docs


def render(document: dict[str, Any]) -> str:
    return json.dumps(document, indent=2, sort_keys=True) + "\n"


def main(argv: list[str] | None = None, root: Path | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    base = root or Path.cwd()
    stale: list[str] = []
    for relative, document in documents().items():
        path = base / relative
        content = render(document)
        if "--check" in args:
            if not path.exists() or path.read_text(encoding="utf-8") != content:
                stale.append(relative)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8", newline="\n")
    if stale:
        sys.stderr.write(
            "stale contracts (run python -m continuous_red_teaming.contracts): "
            + ", ".join(stale)
            + "\n"
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
