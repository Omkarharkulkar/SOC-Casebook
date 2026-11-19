# Part A Analysis

## Method

The original Google security notification was reviewed offline using Python's standard-library email parser and command-line inspection.

The analysis covered headers, provider authentication results, routing timestamps, MIME content and URL references.

No email client rendering, link navigation, remote-resource loading, attachment execution, DNS lookup or reputation lookup was performed.

## Reproduction

Run from the CASE-004 directory:

`python3 analysis/sanitize_email.py`

The script reads the private original from `~/case004-private/` and generates the sanitized derivative in `evidence/`.

The original email is not included in the repository.

## Tools

- Python 3 standard library (`email` parser and generator)
- Command-line text review
- SHA-256 integrity verification

## Limitations

The sanitized derivative has been modified and reserialized. Its DKIM signature cannot be independently verified.

The account holder's recognition of the authorization is retrospective user confirmation, not independent forensic verification.

Legacy synthetic exercises are retained separately under `supplementary/SUPP-002/`.

## Sanitizer scope

`sanitize_email.py` was written specifically for the Google security notification examined in CASE-004 Part A. Its redaction rules include Google-specific headers, domains and message identifiers. Do not reuse it for other email samples or Part B evidence without reviewing and adapting the rules and privacy checks for that sample.
