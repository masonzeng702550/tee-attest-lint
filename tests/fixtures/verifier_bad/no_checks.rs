// known-BAD SEV-SNP verifier fixture.
// Receives an attestation report and trusts it blindly — the classic silent
// failure. Expected: every static rule for sev-snp fires (missing checks).

use sev_guest::AttestationReport;

pub fn verify(report: &AttestationReport) -> Result<(), Error> {
    // Parse the report and... just use it. No signature check, no chain, no
    // debug check, no measurement pin, no nonce, no channel binding, no CRL.
    let _measurement = report.measurement;
    let _report_data = report.report_data;
    Ok(())
}
