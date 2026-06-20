from conftest import FIXTURES
from builders import GOOD_MEASUREMENT, build_report, report_data_for

from tee_attest_lint.grader import GradeInputs, grade_report
from tee_attest_lint.policy import load_policy
from tee_attest_lint.platforms import sev_snp
from tee_attest_lint.report import FindingStatus, Verdict

STRICT = str(FIXTURES / "policy" / "strict.yaml")
NONCE = bytes.fromhex("0011223344556677")
PUBKEY = b"-----TLS-PUBKEY-----test-key-----"


def _grade(report_bytes, inp=None):
    policy = load_policy(STRICT)
    rep = sev_snp.parse(report_bytes)
    return grade_report(rep, policy, inp or GradeInputs(), target="mem")


def _by_id(report):
    return {f.rule_id: f for f in report.findings}


def test_offline_clean_report_is_capped_insecure():
    # Everything locally checkable passes, but signature/chain are unverifiable
    # without collateral -> safety cap -> insecure, score == 40.
    rd = report_data_for(PUBKEY, NONCE)
    rb = build_report(measurement=GOOD_MEASUREMENT, report_data=rd)
    inp = GradeInputs(nonce=NONCE, tls_pubkey=PUBKEY)
    report = _grade(rb, inp)

    assert report.verdict == Verdict.INSECURE
    assert report.score == 40
    # local checks passed
    assert "R-MEAS-001" in report.checks_performed
    assert "R-DEBUG-001" in report.checks_performed
    assert "R-BIND-001" in report.checks_performed
    assert "R-FRESH-001" in report.checks_performed
    # crypto checks are explicitly missing, not silently passed
    assert "R-SIG-001" in report.checks_missing
    assert "R-CHAIN-001" in report.checks_missing


def test_debug_report_fails_debug_rule():
    rb = build_report(debug=True)
    report = _grade(rb)
    f = _by_id(report)
    assert f["R-DEBUG-001"].status == FindingStatus.FAILED
    assert report.verdict == Verdict.INSECURE


def test_measurement_mismatch_fails():
    rb = build_report(measurement=bytes.fromhex("cd" * 48))
    report = _grade(rb)
    f = _by_id(report)
    assert f["R-MEAS-001"].status == FindingStatus.FAILED


def test_low_tcb_fails():
    rb = build_report(tcb=(1, 0, 8, 100))  # below strict floor
    report = _grade(rb)
    f = _by_id(report)
    assert f["R-TCB-001"].status == FindingStatus.FAILED


def test_grade_is_deterministic():
    rb = build_report(report_data=report_data_for(PUBKEY, NONCE))
    inp = GradeInputs(nonce=NONCE, tls_pubkey=PUBKEY)
    a = _grade(rb, inp).to_dict()
    b = _grade(rb, inp).to_dict()
    assert a == b


def test_full_collateral_path_is_strong():
    crypto = __import__("importlib").util.find_spec("cryptography")
    if crypto is None:
        import pytest
        pytest.skip("cryptography not installed")

    from cryptography.hazmat.primitives.asymmetric import ec, utils
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    import datetime

    # Build a tiny PKI: root -> VCEK.
    root_key = ec.generate_private_key(ec.SECP384R1())
    vcek_key = ec.generate_private_key(ec.SECP384R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "AMD-ARK-test")])
    not_before = datetime.datetime(2026, 1, 1)
    not_after = datetime.datetime(2030, 1, 1)
    root_cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(root_key.public_key())
        .serial_number(1).not_valid_before(not_before).not_valid_after(not_after)
        .sign(root_key, hashes.SHA384())
    )
    vcek_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "VCEK-test")])
    vcek_cert = (
        x509.CertificateBuilder()
        .subject_name(vcek_name).issuer_name(name)
        .public_key(vcek_key.public_key())
        .serial_number(2).not_valid_before(not_before).not_valid_after(not_after)
        .sign(root_key, hashes.SHA384())
    )
    root_pem = root_cert.public_bytes(serialization.Encoding.PEM)
    vcek_pem = vcek_cert.public_bytes(serialization.Encoding.PEM)

    rd = report_data_for(PUBKEY, NONCE)
    rb = build_report(report_data=rd)
    rep = sev_snp.parse(rb)

    # Sign the grader's signed-bytes stand-in with the VCEK key, store r||s LE.
    from tee_attest_lint.grader import _signed_bytes_placeholder, Collateral, grade_report
    signed = _signed_bytes_placeholder(rep)
    der = vcek_key.sign(signed, ec.ECDSA(hashes.SHA384()))
    r, s = utils.decode_dss_signature(der)
    rep.signature = r.to_bytes(48, "little") + s.to_bytes(48, "little")

    col = Collateral(vcek_pem=vcek_pem, vendor_root_pem=root_pem, crl_pem=b"-----CRL-----")
    inp = GradeInputs(nonce=NONCE, tls_pubkey=PUBKEY, collateral=col)
    policy = load_policy(STRICT)
    report = grade_report(rep, policy, inp, target="mem")

    assert report.score == 100, [f.to_dict() for f in report.findings]
    assert report.verdict == Verdict.STRONG
    assert report.findings == []
