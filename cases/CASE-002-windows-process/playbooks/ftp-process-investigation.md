# Playbook: FTP-Related Process Activity

## Objective

Provide a basic SOC L1 checklist for reviewing suspicious FTP-related process creation alerts on Windows systems.

## Investigation Steps

### 1. Validate the alert
- Record the alert name, severity, timestamp, hostname, and event record ID.
- Identify the detection rule and review the conditions that triggered it.
- Check whether the rule is experimental or marked as `test`.
- Treat the alert as an investigation lead, not proof of malicious activity.

### 2. Review process activity
- Examine the parent and child process relationships and the surrounding process tree.
- Identify which process relationship or rule condition caused the detection.
- Collect and review full executable paths, command lines, user context, and available hashes or signatures internally when authorised. These fields help validate process identity and possible masquerading.
- Check whether the activity is expected for the host and user.
- Store sensitive metadata securely. Sanitise usernames, full paths, and command lines before publishing public reports.

### 3. Correlate supporting evidence
- Review nearby Sysmon and Windows events.
- Check available network connection records.
- Review relevant file activity and authentication events.
- Look for related activity on other systems.
- Use timestamps and event identifiers to correlate records from different sources.

### 4. Assess impact
- Determine whether the activity was authorized and expected.
- Look for supporting evidence of a successful file transfer or subsequent execution.
- Check whether other telemetry indicates access, persistence, or impact.
- Process creation alone does not establish that a file was transferred, a payload executed, or a system was compromised.
- Do not declare compromise based on a single detection.

### 5. Document and escalate
- Preserve relevant logs according to organizational procedures.
- Record the evidence, timestamps, and investigation timeline.
- Document confirmed findings separately from assumptions.
- Record any gaps in available evidence.
- Escalate unexplained or suspicious activity according to organizational procedures.

## Closure Guidance

Close as benign only when supporting evidence adequately explains the activity.

If suspicious activity remains unexplained, escalate for further investigation.

A detection alert alone does not confirm compromise.
