from conftest import FIXTURES
from tee_attest_lint.static_scan import scan


def _ids(report):
    return {f.rule_id for f in report.findings}


def test_good_verifier_has_no_findings():
    report = scan(str(FIXTURES / "verifier_good"), tee="sev-snp")
    assert report.findings == [], _ids(report)
    assert not report.errors


def test_bad_verifier_flags_every_rule():
    report = scan(str(FIXTURES / "verifier_bad" / "no_checks.rs"), tee="sev-snp")
    ids = _ids(report)
    expected = {
        "R-SIG-001", "R-CHAIN-001", "R-DEBUG-001", "R-MEAS-001",
        "R-FRESH-001", "R-BIND-001", "R-REVOKE-001",
    }
    assert ids == expected, f"unexpected: {ids ^ expected}"


def test_missing_signature_check_is_detected():
    report = scan(str(FIXTURES / "verifier_bad" / "no_signature.rs"), tee="sev-snp")
    ids = _ids(report)
    assert "R-SIG-001" in ids
    assert "R-CHAIN-001" in ids
    # this fixture *does* pin measurement and check debug/nonce
    assert "R-MEAS-001" not in ids
    assert "R-DEBUG-001" not in ids


def test_non_verifier_path_reports_error_not_silent_pass():
    report = scan(str(FIXTURES / "policy"), tee="sev-snp")
    assert report.errors
    assert report.findings == []
