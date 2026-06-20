"""Policy linter — detects over-loose attestation policy (SPEC §4).

Structural problems are surfaced as PolicyError by ``policy.load_policy``; this
module assumes a structurally valid policy and only emits lint *findings* for
settings that silently weaken the security guarantee.
"""

from __future__ import annotations

from . import rules
from .policy import WILDCARD_MEASUREMENTS, Policy, PolicyError, load_policy
from .report import Finding, FindingStatus, Location, Report


def _finding(rule_id: str, evidence: str) -> Finding:
    r = rules.get(rule_id)
    return Finding(
        rule_id=r.id,
        title=r.title,
        severity=r.severity,
        status=FindingStatus.MISSING,
        evidence=evidence,
        remediation=r.remediation,
        doc=r.doc,
        location=Location(),
    )


def _measurement_is_wildcard(entry) -> bool:
    if entry in WILDCARD_MEASUREMENTS:
        return True
    if isinstance(entry, str) and entry.strip().lower() in {"*", "any", ""}:
        return True
    if isinstance(entry, dict):
        # mapping form: { "<hex>": ... } — wildcard if any key is a wildcard
        return any(_measurement_is_wildcard(k) for k in entry.keys())
    return False


def lint_policy_obj(policy: Policy, target: str) -> Report:
    report = Report(mode="lint-policy", tee=policy.tee, target=target)
    findings = report.findings

    # R-MEAS-001: wildcard / empty measurements, or pinning disabled.
    measurements = policy.measurements
    if not measurements or all(_measurement_is_wildcard(m) for m in measurements):
        findings.append(
            _finding(
                "R-MEAS-001",
                "identity.measurements is empty or a wildcard — any image is accepted",
            )
        )
    if policy.get("identity", "require_measurement_pin") is False:
        findings.append(
            _finding("R-MEAS-001", "identity.require_measurement_pin is false")
        )

    # R-TCB-001 / R-RESULT-001: missing min_tcb / accepting out-of-date.
    if not policy.get("tcb", "min_tcb"):
        findings.append(_finding("R-TCB-001", "tcb.min_tcb is missing — no TCB floor"))
    if policy.get("tcb", "allow_out_of_date") is True:
        findings.append(
            _finding("R-RESULT-001", "tcb.allow_out_of_date is true — out-of-date TCB accepted")
        )

    # R-DEBUG-001: debug allowed / validated not required.
    if policy.get("state", "allow_debug") is True:
        findings.append(_finding("R-DEBUG-001", "state.allow_debug is true"))
    if policy.get("state", "require_validated") is False:
        findings.append(_finding("R-DEBUG-001", "state.require_validated is false"))

    # R-FRESH-001: nonce not required.
    if policy.get("freshness", "require_nonce") is not True:
        findings.append(
            _finding("R-FRESH-001", "freshness.require_nonce is not true — replay is possible")
        )

    # R-BIND-001: channel binding not required.
    if policy.get("channel_binding", "require_report_data_binding") is not True:
        findings.append(
            _finding(
                "R-BIND-001",
                "channel_binding.require_report_data_binding is not true — report not tied to the channel",
            )
        )

    # R-REVOKE-001: revocation checks disabled.
    if policy.get("revocation", "check_crl") is False:
        findings.append(_finding("R-REVOKE-001", "revocation.check_crl is false"))

    # R-CHAIN-001: chain-to-root not required.
    if policy.get("trust_roots", "require_chain_to_root") is False:
        findings.append(
            _finding("R-CHAIN-001", "trust_roots.require_chain_to_root is false")
        )

    # R-BOOT-001: kernel cmdline not locked / wildcard cmdline hashes.
    boot = policy.section("boot")
    if boot:
        if boot.get("lock_kernel_cmdline") is False:
            findings.append(_finding("R-BOOT-001", "boot.lock_kernel_cmdline is false"))
        allowed = boot.get("allowed_cmdline_hashes")
        if isinstance(allowed, list) and any(
            isinstance(h, str) and h.strip() in {"*", ""} for h in allowed
        ):
            findings.append(
                _finding("R-BOOT-001", "boot.allowed_cmdline_hashes contains a wildcard")
            )

    report.checks_missing = sorted({f.rule_id for f in findings})
    return report


def lint_policy_file(path: str) -> Report:
    """Convenience wrapper. Raises PolicyError on structural problems."""
    policy = load_policy(path)
    return lint_policy_obj(policy, target=path)
