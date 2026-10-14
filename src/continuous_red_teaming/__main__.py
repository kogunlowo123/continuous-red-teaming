"""Process entry point: ``python -m continuous_red_teaming``."""

from __future__ import annotations

import os

import uvicorn
from agentic_core.observability import configure_logging, configure_telemetry
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

from continuous_red_teaming import __version__
from continuous_red_teaming.api.app import create_app
from continuous_red_teaming.config import Settings
from continuous_red_teaming.runtime.container import build_container


def main() -> None:
    settings = Settings()  # populated from CRT_* environment variables
    configure_logging(
        service="continuous-red-teaming", environment=settings.environment, level=settings.log_level
    )
    exporter = None
    if settings.otlp_endpoint:
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (  # noqa: PLC0415
            OTLPSpanExporter,
        )

        exporter = OTLPSpanExporter(endpoint=settings.otlp_endpoint)
    configure_telemetry(
        service_name="continuous-red-teaming",
        service_version=__version__,
        environment=settings.environment,
        span_exporter=exporter,
    )
    app = create_app(
        lambda: build_container(settings), mcp_allowed_hosts=settings.mcp_allowed_hosts
    )
    FastAPIInstrumentor.instrument_app(app, excluded_urls="healthz,readyz,metrics")
    uvicorn.run(
        app,
        host=os.environ.get("CRT_HOST", "127.0.0.1"),
        port=int(os.environ.get("CRT_PORT", "8080")),
        proxy_headers=True,
        forwarded_allow_ips=os.environ.get("CRT_FORWARDED_ALLOW_IPS", "127.0.0.1"),
        log_config=None,
        access_log=False,
    )


if __name__ == "__main__":
    main()
