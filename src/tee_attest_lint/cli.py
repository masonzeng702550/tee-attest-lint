"""Command-line interface (SPEC §7).

Exit codes:
    0  no problem
    1  findings at/above threshold, or grade is weak|insecure
    2  execution error (parse failure, missing collateral, ...)
"""

from __future__ import annotations

import argparse
import sys

from . import __version__, rules
from .grader import Collateral, GradeInputs, grade_file
from .policy import PolicyError, load_policy
from .policy_lint import lint_policy_obj
from .platforms.sev_snp import ReportParseError
from .report import Report, Verdict, render_text
from .static_scan import scan as static_scan

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

_SEV_THRESHOLD_RANK = {"medium": 0, "high": 1, "critical": 2}


def _emit(report: Report, fmt: str) -> None:
    if fmt == "json":
        print(report.to_json())
    else:
        print(render_text(report))


def _exit_for_findings(report: Report, threshold: str) -> int:
    if report.errors:
        return EXIT_ERROR
    min_rank = _SEV_THRESHOLD_RANK[threshold]
    for f in report.findings:
        if f.severity.rank >= min_rank:
            return EXIT_FINDINGS
    return EXIT_OK


# --- subcommands ------------------------------------------------------------

def _cmd_scan(args: argparse.Namespace) -> int:
    report = static_scan(args.path, tee=args.tee)
    _emit(report, args.format)
    return _exit_for_findings(report, args.severity_threshold)


def _cmd_lint_policy(args: argparse.Namespace) -> int:
    try:
        policy = load_policy(args.policy)
    except PolicyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    report = lint_policy_obj(policy, target=args.policy)
    _emit(report, args.format)
    return _exit_for_findings(report, "medium")


def _read_bytes(path: str | None) -> bytes | None:
    if not path:
        return None
    with open(path, "rb") as fh:
        return fh.read()


def _cmd_grade(args: argparse.Namespace) -> int:
    try:
        policy = load_policy(args.policy)
    except PolicyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    nonce = bytes.fromhex(args.nonce) if args.nonce else None
    tls_pubkey = _read_bytes(args.tls_pubkey)
    collateral = Collateral(
        vcek_pem=_read_bytes(args.vcek),
        vendor_root_pem=_read_bytes(args.trust_root),
        crl_pem=_read_bytes(args.crl),
    )
    inputs = GradeInputs(nonce=nonce, tls_pubkey=tls_pubkey, collateral=collateral)

    try:
        report = grade_file(args.report, policy, inputs)
    except ReportParseError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    _emit(report, args.format)
    if report.verdict in (Verdict.WEAK, Verdict.INSECURE):
        return EXIT_FINDINGS
    return EXIT_OK


def _cmd_rules(args: argparse.Namespace) -> int:
    selected = rules.for_platform(args.tee)
    if args.format == "json":
        import json

        payload = [
            {
                "id": r.id,
                "title": r.title,
                "severity": r.severity.value,
                "modes": [m.value for m in r.modes],
                "platforms": list(r.platforms),
                "rationale": r.rationale,
                "remediation": r.remediation,
                "doc": r.doc,
            }
            for r in selected
        ]
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        for r in selected:
            modes = "".join(m.value[0].upper() for m in r.modes)
            print(f"{r.id:<13} [{r.severity.value:<8}] ({modes})  {r.title}")
    return EXIT_OK


def _cmd_version(args: argparse.Namespace) -> int:
    print(f"tee-attest-lint {__version__}")
    return EXIT_OK


# --- parser -----------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="attest-lint",
        description="Lint and grade confidential-computing attestation verifiers.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    sc = sub.add_parser("scan", help="static-scan verifier source")
    sc.add_argument("path")
    sc.add_argument("--tee", choices=["sev-snp", "tdx", "sgx"], default="sev-snp")
    sc.add_argument("--format", choices=["json", "text"], default="text")
    sc.add_argument(
        "--severity-threshold",
        choices=["critical", "high", "medium"],
        default="medium",
    )
    sc.add_argument("--baseline", help="baseline file (reserved for P2)")
    sc.set_defaults(func=_cmd_scan)

    lp = sub.add_parser("lint-policy", help="validate and lint an attestation policy")
    lp.add_argument("policy")
    lp.add_argument("--format", choices=["json", "text"], default="text")
    lp.set_defaults(func=_cmd_lint_policy)

    gr = sub.add_parser("grade", help="grade a real report against a policy")
    gr.add_argument("report")
    gr.add_argument("--policy", required=True)
    gr.add_argument("--nonce", help="challenge nonce (hex)")
    gr.add_argument("--tls-pubkey", help="TLS public-key file for channel binding")
    gr.add_argument("--vcek", help="VCEK certificate (PEM) for signature verification")
    gr.add_argument("--trust-root", help="vendor root certificate (PEM)")
    gr.add_argument("--crl", help="CRL (PEM) for revocation checks")
    gr.add_argument("--format", choices=["json", "text"], default="text")
    gr.set_defaults(func=_cmd_grade)

    rl = sub.add_parser("rules", help="list the rule catalog")
    rl.add_argument("--tee", choices=["sev-snp", "tdx", "sgx"], default=None)
    rl.add_argument("--format", choices=["json", "text"], default="text")
    rl.set_defaults(func=_cmd_rules)

    vs = sub.add_parser("version", help="print version")
    vs.set_defaults(func=_cmd_version)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
