# Part A Analysis

## Method
The raw `.eml` was parsed offline using Python's standard-library email parser. Header fields and plain-text body were reviewed. No email client, HTML rendering, remote-resource loading, URL navigation, attachment execution, DNS, or reputation lookups were used.

## Reproduction
Run from the case directory:
`python3 analysis/parse_control.py`

## Tools
- Python 3 standard library (`email` parser)
- Command-line text review
- SHA-256 integrity manifest

## Limitations
The email is synthetic. Authentication and routing values are illustrative; no real SPF, DKIM, DMARC or delivery-route validation is possible. The reserved example domain is not a real service. A benign-looking sample does not establish that a real email or sender is safe.

## Part B

`part-b-indicators.csv` records the indicators observed in the synthetic suspicious email. `part-b-report.md` documents the assessment and limitations. Authentication results are simulated; no external enrichment or URL visits were performed.
