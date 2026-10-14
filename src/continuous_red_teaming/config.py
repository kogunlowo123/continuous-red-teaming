"""Runtime settings, read from CRT_* environment variables."""

from __future__ import annotations

from pathlib import Path

from agentic_core.domain.classification import DataClassification
from pydantic import Field, HttpUrl, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from continuous_red_teaming.security.auth import TrustedIssuer


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="CRT_", env_nested_delimiter="__")

    environment: str = "production"
    public_url: HttpUrl = Field(description="Public base URL; advertised in the A2A agent card")
    database_url: str = Field(description="SQLAlchemy async URL, e.g. postgresql+asyncpg://...")

    audit_key_file: Path | None = Field(
        default=None, description="Ed25519 PEM signing audit events and evaluation reports"
    )
    audit_log_path: Path = Path("/var/lib/continuous-red-teaming/audit/audit.jsonl")
    retired_report_keys: dict[str, str] = Field(
        default_factory=dict,
        description="kid -> base64 raw Ed25519 public key of retired report signing keys",
    )
    dev_ephemeral_keys: bool = Field(
        default=False,
        description="Generate an in-memory signing key at start-up. Refused in production.",
    )

    suites_dir: Path = Path("suites")
    gate_policy_file: Path = Path("policies/release-gate.yaml")
    decision_policy_file: Path = Path("policies/release-decision.yaml")
    access_policy_file: Path = Path("policies/platform-access.yaml")
    target_tool_policy_file: Path = Path("policies/target-tool-policy.yaml")

    trusted_issuers: list[TrustedIssuer] = Field(
        default_factory=list, description="OIDC issuers for people and CI pipelines (JSON list)"
    )
    fabric_url: str | None = Field(default=None, description="agent-identity-fabric base URL")
    fabric_issuer: str | None = Field(default=None, description="iss of fabric credentials")
    fabric_client_id: str | None = None
    fabric_workload_token_file: Path | None = None
    fabric_scope: str | None = None

    target_allowed_hosts: list[str] = Field(default_factory=list)
    allow_insecure_targets: bool = False
    allow_reference_targets: bool = False

    max_probes_per_run: int = Field(default=5000, ge=1, le=20_000)
    probe_concurrency: int = Field(default=8, ge=1, le=64)
    max_active_runs: int = Field(default=4, ge=1, le=64)
    abort_after_consecutive_errors: int = Field(default=20, ge=1, le=10_000)

    providers_file: Path | None = Field(
        default=None, description="agentic-core providers.yaml; enables the LLM rubric judge"
    )
    llm_judge_classification: DataClassification = DataClassification.CONFIDENTIAL

    mcp_allowed_hosts: list[str] = Field(
        default_factory=lambda: ["127.0.0.1:*", "localhost:*"],
        description="Host header values accepted on /mcp (DNS rebinding protection)",
    )
    log_level: str = "INFO"
    otlp_endpoint: str | None = None

    @model_validator(mode="after")
    def _consistent(self) -> Settings:
        production = self.environment == "production"
        if self.dev_ephemeral_keys and production:
            raise ValueError("dev_ephemeral_keys cannot be used in production")
        if not self.dev_ephemeral_keys and self.audit_key_file is None:
            raise ValueError("CRT_AUDIT_KEY_FILE is required unless dev_ephemeral_keys is set")
        if self.allow_insecure_targets and production:
            raise ValueError("allow_insecure_targets cannot be used in production")
        if self.fabric_url and not self.fabric_issuer:
            raise ValueError("CRT_FABRIC_ISSUER is required with CRT_FABRIC_URL")
        if not self.trusted_issuers and not self.fabric_url:
            raise ValueError(
                "configure CRT_TRUSTED_ISSUERS or CRT_FABRIC_URL; no caller could log in"
            )
        return self

    @property
    def public_url_str(self) -> str:
        return str(self.public_url).rstrip("/")
