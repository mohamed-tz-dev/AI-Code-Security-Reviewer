# TODO - AI Code Security Reviewer

## Automated AI Remediation & Code Compare (Side-by-side Diff)

- [x] Verify backend supports patched code field in DB (`secure_patch`).
- [x] Implement frontend Side-by-side view inside `FindingCard` using:
  - Left (Insecure): `finding.evidence`
  - Right (Secure patch): `finding.secure_patch` (fallback `finding.securePatch`)
- [x] Add CSS for diff view (red/green panels, two-column grid, monospace styling).
- [x] Quick sanity check by running frontend build / dev and opening a scan with AI findings.



