# CASE-001: SSH Authentication and Honeypot Investigation

## Objective

Investigate SSH authentication activity recorded on an Ubuntu lab VM and examine a public SSH honeypot dataset for suspicious login and command activity.

## Scope

- Review SSH authentication and service logs.
- Identify failed and accepted authentication events.
- Examine source addresses, timestamps, and account activity.
- Analyse a public SSH honeypot dataset separately from the lab logs.
- Document findings, limitations, and recommended SOC actions.

## Evidence Sources

This investigation uses two separate sources:

1. **Lab evidence:** SSH authentication events and SSH service journal records collected from the Ubuntu lab VM.
2. **Public evidence:** A publicly available SSH honeypot dataset hosted on Zenodo.

See [`evidence/README.md`](evidence/README.md) for the evidence inventory, collection methods, dataset provenance, and analysis details.

## Tools

- Linux command-line utilities and `journalctl`
- Python standard library
- MiniSOC SSH log parser
- Git for version control

The public dataset was analysed using four Python scripts in the `analysis/` directory.

## Investigation Status

**Complete**

The investigation identified authentication events in the lab logs and suspicious command activity recorded by the public honeypot. The evidence does not establish a confirmed compromise of the lab host or successful payload execution in the honeypot session.

The lab and public dataset findings are assessed separately because they represent different environments.

## Limitations

- Available logs do not establish the intent behind every authentication event.
- Some SSH journal records are not recognized by the current parser.
- The public dataset records honeypot activity and does not establish compromise of a production host.
- Recorded command activity does not prove that a download or execution succeeded.

See [`incident-report.md`](incident-report.md) for the full investigation, findings, verdicts, and recommended actions.
