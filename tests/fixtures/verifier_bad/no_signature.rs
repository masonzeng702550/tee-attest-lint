// known-BAD fixture: checks measurement and debug but FORGETS to verify the
// signature and certificate chain — so a forged report sails through.
// Expected: R-SIG-001 and R-CHAIN-001 fire (among others).

use sev_guest::AttestationReport;

pub fn verify(report: &AttestationReport, nonce: &[u8]) -> Result<(), Error> {
    if report.is_debug() {
        return Err(Error::Debug);
    }
    let expected_measurement = load_expected_measurement();
    if report.measurement != expected_measurement {
        return Err(Error::MeasurementMismatch);
    }
    if !report.report_data.starts_with(nonce) {
        return Err(Error::Stale);
    }
    // BUG: never verifies the report signature or builds the cert chain.
    Ok(())
}
