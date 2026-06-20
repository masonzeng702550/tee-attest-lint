import pytest

from conftest import FIXTURES
from tee_attest_lint.policy import PolicyError, load_policy
from tee_attest_lint.policy_lint import lint_policy_file


def _rule_ids(report):
    return {f.rule_id for f in report.findings}


def test_loose_policy_flags_all_weaknesses():
    report = lint_policy_file(str(FIXTURES / "policy" / "loose.yaml"))
    ids = _rule_ids(report)
    expected = {
        "R-MEAS-001", "R-TCB-001", "R-RESULT-001", "R-DEBUG-001",
        "R-FRESH-001", "R-BIND-001", "R-REVOKE-001", "R-CHAIN-001", "R-BOOT-001",
    }
    assert expected.issubset(ids), f"missing: {expected - ids}"


def test_strict_policy_is_clean():
    report = lint_policy_file(str(FIXTURES / "policy" / "strict.yaml"))
    assert report.findings == []
    assert report.checks_missing == []


def test_malformed_policy_raises_schema_error():
    with pytest.raises(PolicyError):
        load_policy(str(FIXTURES / "policy" / "malformed.yaml"))


def test_lint_report_mode_and_tee():
    report = lint_policy_file(str(FIXTURES / "policy" / "strict.yaml"))
    assert report.mode == "lint-policy"
    assert report.tee == "sev-snp"
