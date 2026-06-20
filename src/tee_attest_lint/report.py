"""Unified report / score schema shared by all three modes.

The JSON shape is stable so static findings, policy defects and runtime gaps
can be cross-referenced by rule_id (see SPEC §8).
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

from . import TOOL_NAME, __version__
from .rules import Severity


class FindingStatus(str, Enum):
    MISSING = "missing"   # check absent (static gap / policy gap / not required)
    FAILED = "failed"     # check ran but the report failed it
    PASSED = "passed"     # check ran and passed (runtime only)


class Verdict(str, Enum):
    STRONG = "strong"        # >= 90
    ADEQUATE = "adequate"    # 70-89
    WEAK = "weak"            # 40-69
    INSECURE = "insecure"    # < 40


@dataclass
class Location:
    file: str | None = None
    line: int | None = None
    step: str | None = None  # runtime: which verification step

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    status: FindingStatus
    evidence: str
    remediation: str
    doc: str
    location: Location = field(default_factory=Location)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "status": self.status.value,
            "location": self.location.to_dict(),
            "evidence": self.evidence,
            "remediation": self.remediation,
            "doc": self.doc,
        }


@dataclass
class Report:
    mode: str                       # scan | lint-policy | grade
    tee: str
    target: str
    findings: list[Finding] = field(default_factory=list)
    checks_performed: list[str] = field(default_factory=list)
    checks_missing: list[str] = field(default_factory=list)
    score: int | None = None        # grade mode only
    verdict: Verdict | None = None  # grade mode only
    errors: list[str] = field(default_factory=list)

    def counts(self) -> dict[str, int]:
        c = {"critical": 0, "high": 0, "medium": 0}
        for f in self.findings:
            c[f.severity.value] += 1
        return c

    def to_dict(self) -> dict[str, Any]:
        summary: dict[str, Any] = {"counts": self.counts()}
        if self.verdict is not None:
            summary["verdict"] = self.verdict.value
        if self.score is not None:
            summary["score"] = self.score
        out: dict[str, Any] = {
            "tool": TOOL_NAME,
            "version": __version__,
            "mode": self.mode,
            "tee": self.tee,
            "target": self.target,
            "summary": summary,
            "findings": [f.to_dict() for f in self.findings],
            "checks_performed": self.checks_performed,
            "checks_missing": self.checks_missing,
        }
        if self.errors:
            out["errors"] = self.errors
        return out

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Human-readable rendering
# ---------------------------------------------------------------------------

_SEV_LABEL = {
    "critical": "CRIT",
    "high": "HIGH",
    "medium": "MED ",
}


def render_text(report: Report) -> str:
    lines: list[str] = []
    lines.append(f"{TOOL_NAME} {__version__}  ·  mode={report.mode}  tee={report.tee}")
    lines.append(f"target: {report.target}")
    lines.append("")

    if report.verdict is not None:
        lines.append(f"VERDICT: {report.verdict.value.upper()}  (score {report.score}/100)")
        lines.append("")

    c = report.counts()
    lines.append(
        f"findings: {c['critical']} critical, {c['high']} high, {c['medium']} medium"
    )
    lines.append("")

    if report.findings:
        # Sort most severe first, then by rule id for stable output.
        ordered = sorted(
            report.findings,
            key=lambda f: (-f.severity.rank, f.rule_id),
        )
        for f in ordered:
            loc = ""
            if f.location.file:
                loc = f" {f.location.file}"
                if f.location.line:
                    loc += f":{f.location.line}"
            elif f.location.step:
                loc = f" [{f.location.step}]"
            lines.append(
                f"  [{_SEV_LABEL[f.severity.value]}] {f.rule_id} ({f.status.value}){loc}"
            )
            lines.append(f"        {f.title}")
            lines.append(f"        evidence: {f.evidence}")
            lines.append(f"        fix:      {f.remediation}")
            lines.append("")
    else:
        lines.append("  no findings.")
        lines.append("")

    if report.checks_missing:
        lines.append("checks missing: " + ", ".join(report.checks_missing))
    if report.checks_performed:
        lines.append("checks performed: " + ", ".join(report.checks_performed))
    if report.errors:
        lines.append("")
        for e in report.errors:
            lines.append(f"error: {e}")

    return "\n".join(lines)
