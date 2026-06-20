"""Static scanner for attestation *verifier* source.

The MVP uses a pattern/heuristic engine rather than a full data-flow AST pass
(SPEC §6/§10 flag tree-sitter as the eventual upgrade). The engine is
data-driven:

* a file is treated as a *verifier* only if it matches an ``ANCHOR`` pattern
  (it actually handles an attestation report / quote);
* for each rule in the platform's static set, the file must contain at least one
  *satisfaction* pattern proving the corresponding check is present — otherwise a
  ``missing`` finding is emitted at the anchor line.

This deliberately reports "could not confirm the check" rather than pretending a
file is safe (PRD §9: silent failure is the enemy).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from . import rules
from .report import Finding, FindingStatus, Location, Report

# Source extensions we know how to read for the SEV-SNP / DCAP idioms.
SOURCE_SUFFIXES = {".rs", ".c", ".h", ".cc", ".cpp", ".go", ".py"}

# A file is a verifier candidate if any of these appear (sev-guest / DCAP idioms).
ANCHOR = re.compile(
    r"attestation[_ ]?report|attestationreport|snp_report|guest_report|"
    r"parse_report|report_data|launch[_ ]?measurement|sev[_-]?guest|"
    r"verify_report|verify_quote|sev_snp|snp_attestation",
    re.IGNORECASE,
)

# Per-rule satisfaction patterns: presence of ANY proves the check exists.
# Keyed by rule id; only rules listed here are checked statically.
_SAT: dict[str, list[re.Pattern[str]]] = {
    "R-SIG-001": [
        re.compile(p, re.IGNORECASE)
        for p in (
            r"verify[_ ]?signature",
            r"verify[_ ]?vcek",
            r"verify_report_signature",
            r"verify[_ ]?attestation[_ ]?signature",
            r"(vcek|vlek)[^\n]{0,30}verify|verify[^\n]{0,30}(vcek|vlek)",
            r"ecdsa[^\n]{0,20}verify|verify[^\n]{0,20}ecdsa",
            r"qv?l?_?verify_quote",
            r"report\.signature[^\n]{0,30}verify|verify[^\n]{0,30}\.signature",
        )
    ],
    "R-CHAIN-001": [
        re.compile(p, re.IGNORECASE)
        for p in (
            r"verify[_ ]?(cert[_ ]?)?chain",
            r"build[_ ]?chain",
            r"trust[_ ]?anchor",
            r"\bark\b|\bask\b",
            r"root[_ ]?cert",
            r"chain_to_root",
        )
    ],
    "R-DEBUG-001": [
        re.compile(p, re.IGNORECASE)
        for p in (
            r"is_debug|debug_flag|debuggable",
            r"(if|assert|reject|return|panic|bail|err)[^\n]{0,40}debug",
            r"require[_ ]?validated|is_validated|\bvalidated\b",
            r"platform_info[^\n]{0,40}(debug|smt)",
            r"policy[^\n]{0,20}debug",
        )
    ],
    "R-MEAS-001": [
        re.compile(p, re.IGNORECASE)
        for p in (
            r"expected[_ ]?measurement",
            r"measurement[^\n]{0,30}(==|!=|\.eq|ct_eq|constant_time_eq|equals)",
            r"(==|ct_eq|constant_time_eq|assert_eq!)[^\n]{0,30}measurement",
            r"pin[_ ]?measurement|measurement[_ ]?pin",
        )
    ],
    "R-FRESH-001": [
        re.compile(p, re.IGNORECASE)
        for p in (
            r"\bnonce\b",
            r"freshness",
            r"challenge[^\n]{0,20}(==|compare|eq)",
        )
    ],
    "R-BIND-001": [
        re.compile(p, re.IGNORECASE)
        for p in (
            r"report_data[^\n]{0,40}(pubkey|public_key|tls|channel|sha512|sha-512|hash)",
            r"channel[_ ]?binding",
            r"(pubkey|public_key|tls)[^\n]{0,40}report_data",
        )
    ],
    "R-REVOKE-001": [
        re.compile(p, re.IGNORECASE)
        for p in (
            r"\bcrl\b",
            r"revocation|revoked",
            r"collateral",
            r"check_revocation",
        )
    ],
}

# Static rule set per platform (order = report order).
_STATIC_RULES: dict[str, list[str]] = {
    "sev-snp": ["R-SIG-001", "R-CHAIN-001", "R-DEBUG-001", "R-MEAS-001",
                "R-FRESH-001", "R-BIND-001", "R-REVOKE-001"],
    # TDX/SGX scanners are scaffolded for later milestones.
    "tdx": ["R-SIG-001", "R-CHAIN-001", "R-MEAS-001", "R-FRESH-001", "R-REVOKE-001"],
    "sgx": ["R-SIG-001", "R-CHAIN-001", "R-MEAS-001", "R-FRESH-001"],
}


@dataclass
class _FileScan:
    path: str
    anchor_line: int
    satisfied: set[str]


_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_LINE_COMMENT = re.compile(r"//[^\n]*")
_HASH_COMMENT = re.compile(r"#[^\n]*")


def _strip_comments(text: str, suffix: str) -> str:
    """Remove comments so that merely *mentioning* a check in prose does not
    count as the check being present (a key source of false negatives)."""
    text = _BLOCK_COMMENT.sub(" ", text)
    if suffix == ".py":
        text = _HASH_COMMENT.sub(" ", text)
    else:
        text = _LINE_COMMENT.sub(" ", text)
    return text


def _scan_text(path: str, text: str, suffix: str) -> _FileScan | None:
    anchor_line = 0
    for i, line in enumerate(text.splitlines(), start=1):
        if ANCHOR.search(line):
            anchor_line = i
            break
    if anchor_line == 0:
        return None

    code = _strip_comments(text, suffix)
    satisfied = {rid for rid, pats in _SAT.items() if any(p.search(code) for p in pats)}
    return _FileScan(path=path, anchor_line=anchor_line, satisfied=satisfied)


def _iter_source_files(root: Path):
    if root.is_file():
        if root.suffix in SOURCE_SUFFIXES:
            yield root
        return
    for p in sorted(root.rglob("*")):
        if p.is_file() and p.suffix in SOURCE_SUFFIXES:
            yield p


def scan(path: str, tee: str = "sev-snp") -> Report:
    report = Report(mode="scan", tee=tee, target=path)
    rule_ids = _STATIC_RULES.get(tee, _STATIC_RULES["sev-snp"])

    root = Path(path)
    if not root.exists():
        report.errors.append(f"path not found: {path}")
        return report

    file_scans: list[_FileScan] = []
    for src in _iter_source_files(root):
        try:
            text = src.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:  # pragma: no cover - defensive
            report.errors.append(f"cannot read {src}: {exc}")
            continue
        fs = _scan_text(str(src), text, src.suffix)
        if fs is not None:
            file_scans.append(fs)

    if not file_scans:
        # No verifier code recognised — surface it instead of a silent pass.
        report.errors.append(
            "no attestation-verifier code recognised under the target path"
        )
        return report

    for fs in file_scans:
        for rid in rule_ids:
            if rid not in fs.satisfied:
                r = rules.get(rid)
                report.findings.append(
                    Finding(
                        rule_id=r.id,
                        title=r.title,
                        severity=r.severity,
                        status=FindingStatus.MISSING,
                        evidence=(
                            f"file handles an attestation report but no "
                            f"{r.id} check was found"
                        ),
                        remediation=r.remediation,
                        doc=r.doc,
                        location=Location(file=fs.path, line=fs.anchor_line),
                    )
                )

    performed: set[str] = set()
    for fs in file_scans:
        performed |= fs.satisfied
    report.checks_performed = sorted(performed & set(rule_ids))
    report.checks_missing = sorted({f.rule_id for f in report.findings})
    return report
