# CASE-004 Part A — Evidence Handling

## Source and provenance

The original Google security alert is retained privately outside the repository at:

`~/case004-private/Security alert.eml`

The original message was accessed through Gmail's message details / Show original view. The exact local export timestamp was not recorded.

The message Date header was 19 November 2026, 05:58:50 UTC.

Original SHA-256:

`3a8c614c597672a40f17f7c64f7849f88fbe01261fc8b50c13ab297075983ddb`

The original email is not included in this repository.

## Sanitized evidence

`control-google-security-alert-sanitized.eml` is the repository-safe derivative.

It was generated with `analysis/sanitize_email.py`.

The sanitizer:
- Decodes headers before inspection and sanitization.
- Redacts private strings and email identifiers across headers and text bodies.
- Redacts the per-message Google bounce identifier.
- Preserves duplicate headers while rebuilding the message.
- Removes account-bound notification/token headers.
- Removes account-specific avatar paths.
- Reduces URLs to defanged hostnames, removing paths and query parameters.
- Checks decoded headers and text bodies for private values before writing.
- Fails closed if a configured private value remains.

The derivative was parsed successfully. It has been modified and reserialized, so its DKIM signature must not be treated as independently verified.

## Integrity

Sanitized email SHA-256:

`fffb1e5b7834d8aff0cd92348354dc7d4906657259afa8dca9a87e52fb1b8868`

The original and sanitized hashes identify two different files. The original hash is provided for integrity reference; the original content remains private.
