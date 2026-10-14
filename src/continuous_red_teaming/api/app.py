"""FastAPI application factory: REST API, MCP mount, A2A endpoint."""

from __future__ import annotations

import time
from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from contextlib import asynccontextmanager

from agentic_core.observability import bind_correlation_id, get_logger
from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from continuous_red_teaming import __version__
from continuous_red_teaming.api import a2a
from continuous_red_teaming.api.mcp_server import build_mcp_server, mcp_app
from continuous_red_teaming.api.routes import router
from continuous_red_teaming.domain.errors import RedTeamError
from continuous_red_teaming.runtime.container import Container

ContainerFactory = Callable[[], Awaitable[Container]]
DEFAULT_MCP_HOSTS = ("127.0.0.1:*", "localhost:*")

log = get_logger("continuous_red_teaming.api")


def create_app(
    factory: ContainerFactory, *, mcp_allowed_hosts: Sequence[str] = DEFAULT_MCP_HOSTS
) -> FastAPI:
    holder: dict[str, Container] = {}

    def current() -> Container:
        return holder["container"]

    mcp = build_mcp_server(current)
    mcp_asgi = mcp_app(mcp, mcp_allowed_hosts)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        container = await factory()
        holder["container"] = container
        app.state.container = container
        recovered = await container.service.recover_interrupted()
        log.info("startup", version=__version__, recovered_runs=recovered)
        try:
            async with mcp.session_manager.run():
                yield
        finally:
            await container.aclose()

    app = FastAPI(
        title="Continuous Red Teaming",
        version=__version__,
        description=(
            "Autonomous agent validation and release engineering: versioned benign probe "
            "suites, target adapters (HTTP, MCP, A2A), judges, confidence-interval scoring, "
            "regression tracking and a signed release gate."
        ),
        lifespan=lifespan,
    )
    app.include_router(router)
    app.include_router(a2a.router)
    app.mount("/mcp", mcp_asgi)

    @app.middleware("http")
    async def correlation_and_metrics(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        incoming = request.headers.get("x-correlation-id")
        cid = incoming if incoming and len(incoming) <= 64 and incoming.isprintable() else None
        started = time.perf_counter()
        with bind_correlation_id(cid) as bound:
            response = await call_next(request)
        response.headers["X-Correlation-ID"] = bound
        response.headers["X-Content-Type-Options"] = "nosniff"
        route = request.scope.get("route")
        path = getattr(route, "path", "unmatched")
        container: Container | None = getattr(request.app.state, "container", None)
        if container is not None:
            container.metrics.requests.labels(
                request.method, path, str(response.status_code)
            ).observe(time.perf_counter() - started)
        return response

    @app.exception_handler(RedTeamError)
    async def domain_error(_: Request, exc: RedTeamError) -> JSONResponse:
        headers = {"WWW-Authenticate": "Bearer"} if exc.status == 401 else None
        if exc.status == 429:
            headers = {"Retry-After": "30"}
        return JSONResponse(
            status_code=exc.status,
            content={"error": exc.code, "error_description": exc.message},
            headers=headers,
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={
                "error": "invalid_request",
                "error_description": "request failed validation",
                "details": [
                    {"loc": list(e.get("loc", ())), "msg": str(e.get("msg", ""))}
                    for e in exc.errors()
                ],
            },
        )

    return app
