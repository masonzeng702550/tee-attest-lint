"""Attestation policy: loading, schema validation, and a typed view.

The policy schema (SPEC §4) is shared across platforms; platform-specific fields
live under platform-aware sub-blocks. We keep a hand-written validator rather
than pulling a JSON-Schema dependency so structural errors and over-loose
findings stay cleanly separated (the former are schema errors, the latter lint
findings produced in ``policy_lint``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import yaml

API_VERSION = "attest-lint/v1"
KIND = "AttestationPolicy"
SUPPORTED_TEES = ("sev-snp", "tdx", "sgx")

WILDCARD_MEASUREMENTS = {"*", "any", "", None}


class PolicyError(Exception):
    """Raised on structural (schema) errors — distinct from lint findings."""


@dataclass
class Policy:
    raw: dict[str, Any]
    tee: str
    spec: dict[str, Any] = field(default_factory=dict)

    # convenience accessors -------------------------------------------------
    def section(self, name: str) -> dict[str, Any]:
        val = self.spec.get(name)
        return val if isinstance(val, dict) else {}

    @property
    def measurements(self) -> list[Any]:
        ids = self.section("identity").get("measurements")
        return ids if isinstance(ids, list) else []

    def get(self, *path: str, default: Any = None) -> Any:
        node: Any = self.spec
        for key in path:
            if not isinstance(node, dict):
                return default
            node = node.get(key)
        return node if node is not None else default


def load_policy(path: str) -> Policy:
    """Load and structurally validate a policy file. Raises PolicyError on
    schema problems (missing apiVersion, wrong kind, unknown tee, ...)."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except FileNotFoundError as exc:
        raise PolicyError(f"policy file not found: {path}") from exc
    except yaml.YAMLError as exc:
        raise PolicyError(f"invalid YAML in {path}: {exc}") from exc

    return parse_policy(data)


def parse_policy(data: Any) -> Policy:
    if not isinstance(data, dict):
        raise PolicyError("policy must be a mapping at the top level")

    api = data.get("apiVersion")
    if api != API_VERSION:
        raise PolicyError(
            f"unsupported apiVersion {api!r}; expected {API_VERSION!r}"
        )
    if data.get("kind") != KIND:
        raise PolicyError(f"kind must be {KIND!r}")

    spec = data.get("spec")
    if not isinstance(spec, dict):
        raise PolicyError("spec block is required and must be a mapping")

    tee = spec.get("tee")
    if tee not in SUPPORTED_TEES:
        raise PolicyError(
            f"spec.tee must be one of {SUPPORTED_TEES}; got {tee!r}"
        )

    # identity.measurements must exist (its *content* — wildcards etc. — is a
    # lint concern, handled separately).
    identity = spec.get("identity")
    if not isinstance(identity, dict) or "measurements" not in identity:
        raise PolicyError("spec.identity.measurements is required")

    return Policy(raw=data, tee=tee, spec=spec)
