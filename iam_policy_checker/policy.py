"""Loading and normalising IAM policy documents."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from typing import Any


class PolicyError(ValueError):
    """Raised when a document is not a usable IAM policy."""


def _as_list(value: Any) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


@dataclass
class Statement:
    """One policy statement with every list-or-string field normalised to a list."""

    index: int
    effect: str
    sid: str | None = None
    actions: list[str] = field(default_factory=list)
    not_actions: list[str] = field(default_factory=list)
    resources: list[str] = field(default_factory=list)
    not_resources: list[str] = field(default_factory=list)
    principals: list[str] = field(default_factory=list)
    has_principal: bool = False
    condition: dict | None = None

    @property
    def is_allow(self) -> bool:
        return self.effect == "Allow"

    @property
    def label(self) -> str:
        return f"Statement[{self.index}]" + (f" ({self.sid})" if self.sid else "")

    @property
    def all_resources(self) -> bool:
        """True when the statement applies to every resource."""
        return bool(self.not_resources) or "*" in self.resources

    def matches_action(self, action: str) -> bool:
        """Whether this statement's Action/NotAction covers a concrete action."""
        if self.not_actions:
            return not any(_action_match(p, action) for p in self.not_actions)
        return any(_action_match(p, action) for p in self.actions)


@dataclass
class Policy:
    version: str | None
    statements: list[Statement]
    source: str = "<policy>"

    @property
    def allow_statements(self) -> list[Statement]:
        return [s for s in self.statements if s.is_allow]

    @property
    def deny_statements(self) -> list[Statement]:
        return [s for s in self.statements if not s.is_allow]


def _action_match(pattern: str, action: str) -> bool:
    # IAM action names are case-insensitive and support * and ? wildcards.
    return fnmatchcase(action.lower(), pattern.lower())


def _principals(raw: Any) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, str):
        return [raw]
    if isinstance(raw, dict):
        values: list[str] = []
        for value in raw.values():
            values.extend(str(v) for v in _as_list(value))
        return values
    raise PolicyError(f"Unsupported Principal value: {raw!r}")


def _unwrap(doc: Any) -> Any:
    """Accept common AWS CLI wrappers around the policy document itself."""
    if isinstance(doc, dict):
        if "PolicyVersion" in doc and isinstance(doc["PolicyVersion"], dict):
            doc = doc["PolicyVersion"].get("Document", doc)
        elif "PolicyDocument" in doc:
            doc = doc["PolicyDocument"]
    if isinstance(doc, str):
        try:
            doc = json.loads(doc)
        except json.JSONDecodeError as exc:
            raise PolicyError(f"Embedded policy document is not valid JSON: {exc}") from exc
    return doc


def parse_policy(doc: Any, source: str = "<policy>") -> Policy:
    """Build a :class:`Policy` from a decoded JSON object."""
    doc = _unwrap(doc)
    if not isinstance(doc, dict):
        raise PolicyError("Policy document must be a JSON object")
    if "Statement" not in doc:
        raise PolicyError("Policy document has no 'Statement' element")

    statements = []
    for index, raw in enumerate(_as_list(doc["Statement"])):
        if not isinstance(raw, dict):
            raise PolicyError(f"Statement[{index}] must be a JSON object")
        effect = raw.get("Effect")
        if effect not in ("Allow", "Deny"):
            raise PolicyError(f"Statement[{index}] has invalid Effect {effect!r}")
        if "Action" not in raw and "NotAction" not in raw:
            raise PolicyError(f"Statement[{index}] has neither Action nor NotAction")
        statements.append(
            Statement(
                index=index,
                effect=effect,
                sid=raw.get("Sid"),
                actions=[str(a) for a in _as_list(raw.get("Action"))],
                not_actions=[str(a) for a in _as_list(raw.get("NotAction"))],
                resources=[str(r) for r in _as_list(raw.get("Resource"))],
                not_resources=[str(r) for r in _as_list(raw.get("NotResource"))],
                principals=_principals(raw.get("Principal")),
                has_principal="Principal" in raw or "NotPrincipal" in raw,
                condition=raw.get("Condition") or None,
            )
        )
    return Policy(version=doc.get("Version"), statements=statements, source=source)


def load_policy(text: str, source: str = "<policy>") -> Policy:
    """Parse a policy from JSON text."""
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise PolicyError(f"Invalid JSON: {exc}") from exc
    return parse_policy(doc, source=source)
