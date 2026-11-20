# CASE-004 Part B Evidence

## Source

Phishing Pot public dataset:
https://github.com/rf-peixoto/phishing_pot

Dataset commit:
78be141545ed9e56eefb857808ac78e83eb81b81

Collection/analysis date: 20 November 2026

Original sample:
email/sample-1000.eml

Original SHA-256:
69feb34529b2ea44d90d1b3592935c32e22e968f36829e5f322281641c69450a

The original email is retained outside this repository.

## Collection and Analysis

The sample was retrieved from the public dataset and analyzed offline using Python's email parsing libraries.

Headers, MIME structure, message text, link hostname, authentication results and sending infrastructure were examined.

No links were visited and no attachments were executed.

## Privacy

The dataset test recipient phishing@pot is retained as it is part of the sample context.

The complete original email is not published in this repository.

## Reproducibility

The original sample is excluded from this repository. Retrieve it from the pinned dataset source and verify its SHA-256 hash before analysis. Run the offline analyzer from the `analysis` directory. Tests can be run with:

```bash
python3 -m unittest discover -s tests -v
```

Do not visit embedded links or execute attachments.

## License and Attribution

Source: Phishing Pot — rf-peixoto/phishing_pot.

The dataset documentation identifies CC BY-NC 4.0. License: https://creativecommons.org/licenses/by-nc/4.0/. Attribution is retained, and the original sample is not redistributed here.
