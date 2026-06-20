"""Declarative rule catalog.

Every rule is data: an ID, the platforms it applies to, the modes it runs in,
a severity, the principle (why it is dangerous), and a remediation hint. The
catalog is deliberately decoupled from the engines so it can track vendor spec
changes without touching detection code.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"   # security guarantee reduced to zero
    HIGH = "high"           # significantly weakened
    MEDIUM = "medium"       # situational risk

    @property
    def rank(self) -> int:
        return {"medium": 0, "high": 1, "critical": 2}[self.value]


class Mode(str, Enum):
    STATIC = "static"
    POLICY = "policy"
    RUNTIME = "runtime"


DOC_BASE = "https://github.com/masonzeng702550/tee-attest-lint/blob/main/docs/rules"


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: Severity
    modes: tuple[Mode, ...]
    platforms: tuple[str, ...]
    rationale: str
    remediation: str

    @property
    def doc(self) -> str:
        return f"{DOC_BASE}/{self.id}.md"

    def applies_to(self, mode: Mode) -> bool:
        return mode in self.modes


ALL_PLATFORMS = ("sev-snp", "tdx", "sgx")

# Critical rules whose absence/failure caps the runtime score (safety cap).
CRITICAL_RUNTIME_RULES = ("R-SIG-001", "R-CHAIN-001", "R-DEBUG-001", "R-MEAS-001", "R-BIND-001")


_CATALOG: tuple[Rule, ...] = (
    Rule(
        id="R-SIG-001",
        title="report/quote signature not verified",
        severity=Severity.CRITICAL,
        modes=(Mode.STATIC, Mode.RUNTIME),
        platforms=ALL_PLATFORMS,
        rationale=(
            "Skipping signature verification means anyone can forge a report; "
            "attestation fails completely and silently."
        ),
        remediation="Verify the report signature with the VCEK/VLEK (SEV-SNP) or "
        "PCK (TDX/SGX) public key and check the result.",
    ),
    Rule(
        id="R-CHAIN-001",
        title="certificate chain not anchored to the vendor root",
        severity=Severity.CRITICAL,
        modes=(Mode.STATIC, Mode.RUNTIME),
        platforms=ALL_PLATFORMS,
        rationale=(
            "If VCEK/VLEK or PCK does not chain to AMD ARK/ASK or the Intel PCS "
            "root, you are trusting an unknown issuer."
        ),
        remediation="Build and verify the certificate chain to a built-in vendor "
        "root (ARK/ASK or PCS); never trust a hard-coded or caller-supplied root.",
    ),
    Rule(
        id="R-DEBUG-001",
        title="DEBUG / UNVALIDATED state accepted",
        severity=Severity.CRITICAL,
        modes=(Mode.STATIC, Mode.POLICY, Mode.RUNTIME),
        platforms=ALL_PLATFORMS,
        rationale=(
            "A DEBUG TEE can be inspected and injected; UNVALIDATED means the TCB "
            "was never checked. Accepting either destroys isolation."
        ),
        remediation="Reject reports whose policy/flags indicate DEBUG or that are "
        "not VALIDATED.",
    ),
    Rule(
        id="R-MEAS-001",
        title="measurement not pinned / compared",
        severity=Severity.CRITICAL,
        modes=(Mode.STATIC, Mode.POLICY, Mode.RUNTIME),
        platforms=ALL_PLATFORMS,
        rationale=(
            "Without comparing MRENCLAVE / MRTD / launch measurement you accept "
            "any image — an attacker can swap in a malicious workload."
        ),
        remediation="Compare the reported measurement byte-for-byte against the "
        "expected value(s) from policy; never use a wildcard.",
    ),
    Rule(
        id="R-FRESH-001",
        title="missing nonce / freshness",
        severity=Severity.HIGH,
        modes=(Mode.STATIC, Mode.POLICY, Mode.RUNTIME),
        platforms=ALL_PLATFORMS,
        rationale=(
            "Without a challenge nonce an attacker can replay an old but valid "
            "report and bypass liveness."
        ),
        remediation="Bind a caller-supplied nonce into report_data and compare it "
        "on every verification.",
    ),
    Rule(
        id="R-TCB-001",
        title="TCB below minimum accepted",
        severity=Severity.HIGH,
        modes=(Mode.STATIC, Mode.POLICY, Mode.RUNTIME),
        platforms=ALL_PLATFORMS,
        rationale=(
            "Old TCB contains known vulnerabilities; no lower bound means "
            "accepting exploitable firmware/microcode."
        ),
        remediation="Require reported TCB >= policy min_tcb for every component.",
    ),
    Rule(
        id="R-REVOKE-001",
        title="collateral / CRL revocation not handled",
        severity=Severity.HIGH,
        modes=(Mode.STATIC, Mode.RUNTIME),
        platforms=ALL_PLATFORMS,
        rationale=(
            "Skipping revocation means revoked VCEK/PCK certs are still accepted; "
            "the revocation mechanism becomes a no-op."
        ),
        remediation="Fetch and apply CRL/collateral; fail when a cert is revoked.",
    ),
    Rule(
        id="R-BIND-001",
        title="report_data not bound to the TLS channel public key",
        severity=Severity.CRITICAL,
        modes=(Mode.STATIC, Mode.RUNTIME),
        platforms=ALL_PLATFORMS,
        rationale=(
            "If attestation is decoupled from the secure channel, a MITM can "
            "relay a legitimate report onto its own channel."
        ),
        remediation="Set the expected report_data to a hash of the local TLS "
        "public key (channel binding) and compare it.",
    ),
    Rule(
        id="R-BOOT-001",
        title="policy allows mutable boot parameters / unlocked kernel cmdline",
        severity=Severity.HIGH,
        modes=(Mode.STATIC, Mode.POLICY),
        platforms=ALL_PLATFORMS,
        rationale=(
            "An unlocked cmdline lets an attacker inject init=, disable dm-verity, "
            "etc. — the boot chain is tampered while the measurement still 'passes'."
        ),
        remediation="Lock the kernel cmdline and enumerate allowed cmdline hashes "
        "in policy.",
    ),
    Rule(
        id="R-RESULT-001",
        title="structured verification result ignored",
        severity=Severity.HIGH,
        modes=(Mode.STATIC, Mode.RUNTIME),
        platforms=ALL_PLATFORMS,
        rationale=(
            "DCAP/QVL return a structure (TCB status, advisory IDs), not a bool. "
            "Checking only 'did it throw' lets OUT_OF_DATE / SW_HARDENING_NEEDED "
            "through."
        ),
        remediation="Inspect the returned status/advisory fields and treat any "
        "non-OK status as a defect.",
    ),
    Rule(
        id="R-ALG-001",
        title="weak / arbitrary signature or measurement algorithm accepted",
        severity=Severity.MEDIUM,
        modes=(Mode.STATIC,),
        platforms=ALL_PLATFORMS,
        rationale="Accepting a downgraded algorithm weakens the cryptographic "
        "guarantee.",
        remediation="Pin the expected algorithm; never accept a caller-specified "
        "algorithm.",
    ),
)

BY_ID: dict[str, Rule] = {r.id: r for r in _CATALOG}


def all_rules() -> tuple[Rule, ...]:
    return _CATALOG


def get(rule_id: str) -> Rule:
    return BY_ID[rule_id]


def for_platform(platform: str | None) -> list[Rule]:
    if platform is None:
        return list(_CATALOG)
    return [r for r in _CATALOG if platform in r.platforms]
