# CASE-004 Part A — Evidence Handling

## Source
The original Google security alert was retained privately outside the repository at `~/case004-private/Security alert.eml`. It is not included in this casebook.

## Sanitized evidence
`control-google-security-alert-sanitized.eml` is the repository-safe derivative.

It was generated using `analysis/sanitize_email.py` with Python's email parser. The sanitization process:
- Redacts the recipient and configured private strings across headers and body.
- Preserves the Google sender and relevant authentication/domain evidence.
- Preserves duplicate Received headers while sanitizing their contents.
- Removes account-bound notification/token headers.
- Removes account-specific avatar paths.
- Reduces URLs to defanged hostnames, removing paths and query parameters.
- Runs a private-string check before writing the output.

The sanitized derivative was parsed successfully. Its DKIM signature must not be treated as independently verified after sanitization or reserialization.

## Integrity
Sanitized email SHA-256:

`fbb5ca5795947b0e13c7e6c72d718bb4cb78c135d6e9bd4fde64f9136b82f5f3`

The original email's hash is retained only in the private working record and is not reproduced here.
