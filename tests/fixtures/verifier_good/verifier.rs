// known-GOOD SEV-SNP verifier fixture.
// Performs every check the static scanner looks for. Expected: zero findings.

use sev_guest::{AttestationReport, Vcek};

pub fn verify(report: &AttestationReport, nonce: &[u8], tls_pubkey: &[u8]) -> Result<(), Error> {
    // R-SIG-001: verify the report signature with the VCEK.
    let vcek = Vcek::load()?;
    verify_signature(report, &vcek)?;

    // R-CHAIN-001: chain VCEK to the AMD ARK/ASK root.
    verify_cert_chain(&vcek, amd_ark_root())?;

    // R-DEBUG-001: reject DEBUG / unvalidated guests.
    if report.is_debug() || !report.is_validated() {
        return Err(Error::DebugOrUnvalidated);
    }

    // R-MEAS-001: pin the launch measurement (constant-time compare).
    let expected_measurement = load_expected_measurement();
    if !constant_time_eq(&report.measurement, &expected_measurement) {
        return Err(Error::MeasurementMismatch);
    }

    // R-FRESH-001: bind the challenge nonce into report_data.
    if !report.report_data.starts_with(nonce) {
        return Err(Error::StaleReport);
    }

    // R-BIND-001: report_data must bind the TLS channel public key.
    let bound = sha512(tls_pubkey);
    if report.report_data[..64] != bound[..] {
        return Err(Error::ChannelBindingMismatch);
    }

    // R-REVOKE-001: apply CRL / collateral revocation.
    let crl = fetch_collateral_crl()?;
    if crl.is_revoked(&vcek) {
        return Err(Error::Revoked);
    }

    Ok(())
}
