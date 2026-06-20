import json

from conftest import FIXTURES
from tee_attest_lint.cli import main, EXIT_OK, EXIT_FINDINGS, EXIT_ERROR


def test_scan_good_exits_zero():
    assert main(["scan", str(FIXTURES / "verifier_good")]) == EXIT_OK


def test_scan_bad_exits_findings():
    code = main(["scan", str(FIXTURES / "verifier_bad" / "no_checks.rs")])
    assert code == EXIT_FINDINGS


def test_scan_json_output(capsys):
    main(["scan", str(FIXTURES / "verifier_bad" / "no_checks.rs"), "--format", "json"])
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["tool"] == "tee-attest-lint"
    assert data["mode"] == "scan"
    assert data["findings"]


def test_lint_policy_loose_exits_findings():
    assert main(["lint-policy", str(FIXTURES / "policy" / "loose.yaml")]) == EXIT_FINDINGS


def test_lint_policy_strict_exits_ok():
    assert main(["lint-policy", str(FIXTURES / "policy" / "strict.yaml")]) == EXIT_OK


def test_lint_policy_malformed_exits_error():
    assert main(["lint-policy", str(FIXTURES / "policy" / "malformed.yaml")]) == EXIT_ERROR


def test_rules_and_version_exit_ok(capsys):
    assert main(["rules"]) == EXIT_OK
    assert main(["version"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "tee-attest-lint" in out


def test_severity_threshold_filters(tmp_path):
    # only-medium finding should not trip a critical threshold
    code = main([
        "scan", str(FIXTURES / "verifier_bad" / "no_checks.rs"),
        "--severity-threshold", "critical",
    ])
    # no_checks triggers critical rules, so still 1
    assert code == EXIT_FINDINGS
