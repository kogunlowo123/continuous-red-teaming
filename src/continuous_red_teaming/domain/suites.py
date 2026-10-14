"""Versioned scenario suites loaded from YAML.

A suite is reviewed and versioned like code. Its digest (SHA-256 of the
canonical JSON form) is stored with every run and every signed report, so an
auditor can prove which exact scenarios produced a release decision.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from agentic_core.domain.provenance import canonical_json, content_digest
from agentic_core.policy import PolicySet
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from continuous_red_teaming.domain.errors import NotFoundError, SuiteValidationError
from continuous_red_teaming.domain.models import Category, Scenario, Slug, Version

MAX_PROBES_PER_SUITE = 20_000


class Suite(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: Slug
    version: Version
    description: str = Field(default="", max_length=4000)
    tool_policy: PolicySet | None = None
    scenarios: tuple[Scenario, ...] = Field(min_length=1)

    @field_validator("scenarios")
    @classmethod
    def _unique(cls, scenarios: tuple[Scenario, ...]) -> tuple[Scenario, ...]:
        ids = [s.id for s in scenarios]
        duplicates = sorted({i for i in ids if ids.count(i) > 1})
        if duplicates:
            raise ValueError(f"duplicate scenario ids: {duplicates}")
        total = sum(s.case_count for s in scenarios)
        if total > MAX_PROBES_PER_SUITE:
            raise ValueError(f"suite expands to {total} probes (limit {MAX_PROBES_PER_SUITE})")
        return scenarios

    @property
    def digest(self) -> str:
        return content_digest(canonical_json(self.model_dump(mode="json")))

    @property
    def probe_count(self) -> int:
        return sum(s.case_count for s in self.scenarios)

    @property
    def categories(self) -> tuple[Category, ...]:
        return tuple(sorted({s.category for s in self.scenarios}))

    @classmethod
    def from_yaml(cls, text: str, *, source: str = "<inline>") -> Suite:
        try:
            document = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise SuiteValidationError(f"{source}: not valid YAML: {exc}") from exc
        try:
            return cls.model_validate(document)
        except ValidationError as exc:
            first = exc.errors()[0]
            location = ".".join(str(p) for p in first.get("loc", ()))
            raise SuiteValidationError(
                f"{source}: {location}: {first.get('msg', 'invalid')}"
            ) from exc

    @classmethod
    def from_file(cls, path: Path) -> Suite:
        return cls.from_yaml(path.read_text(encoding="utf-8"), source=path.name)


class SuiteCatalog:
    """All suites in a directory, addressable by ``name`` or ``name@version``."""

    def __init__(self, suites: list[Suite]) -> None:
        self._by_key: dict[tuple[str, str], Suite] = {}
        for suite in suites:
            key = (suite.name, suite.version)
            if key in self._by_key:
                raise SuiteValidationError(f"suite {suite.name}@{suite.version} defined twice")
            self._by_key[key] = suite

    @classmethod
    def from_directory(cls, directory: Path) -> SuiteCatalog:
        if not directory.is_dir():
            raise SuiteValidationError(f"suite directory {directory} does not exist")
        files = sorted([*directory.glob("*.yaml"), *directory.glob("*.yml")])
        return cls([Suite.from_file(path) for path in files])

    def all(self) -> list[Suite]:
        return [self._by_key[k] for k in sorted(self._by_key)]

    def get(self, reference: str) -> Suite:
        """Resolve ``name@version``, or ``name`` to its highest version (natural order)."""
        name, _, version = reference.partition("@")
        if version:
            suite = self._by_key.get((name, version))
            if suite is None:
                raise NotFoundError(f"suite {reference} not found")
            return suite
        candidates = [s for (n, _), s in self._by_key.items() if n == name]
        if not candidates:
            raise NotFoundError(f"suite {name} not found")
        return max(candidates, key=lambda s: _version_key(s.version))


def _version_key(version: str) -> tuple[tuple[int, str], ...]:
    parts = version.replace("-", ".").replace("+", ".").split(".")
    return tuple((int(p), "") if p.isdigit() else (-1, p) for p in parts)
