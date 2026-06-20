"""TEE-Attest-Lint — a linter and security grader for confidential-computing
remote-attestation *verifiers*.

The package is organised around three modes that share one rule catalog and one
report schema:

* ``static_scan``  — lint verifier source for missing/incorrect checks.
* ``policy_lint``  — validate an attestation policy and flag over-loose settings.
* ``grader``       — run a real report through the policy and score it.
"""

__version__ = "0.1.0"
TOOL_NAME = "tee-attest-lint"
