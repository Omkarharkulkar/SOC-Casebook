# Playbook: FTP-Related Process Activity

## Objective

Provide a basic SOC L1 checklist for reviewing suspicious FTP-related process creation alerts on Windows systems.

## Investigation Steps

### 1. Validate the alert
- Record the alert name, severity, timestamp, hostname, and event record ID.
- Identify the detection rule and review its matching conditions.
- Check whether the rule is experimental or marked as test.

### 2. Review process activity
- Examine the parent and child process relationships.
- Review process names, paths, users, and available command-line metadata.
- Check whether the activity is expected for the host and user.

### 3. Correlate supporting evidence
- Review nearby Sysmon and Windows events.
- Check available network connection records.
- Review relevant file activity and authentication events.
- Look for related activity on other systems.

### 4. Assess impact
- Determine whether the activity was authorized.
- Look for evidence supporting successful transfer or execution.
- Do not declare compromise based on a single detection.

### 5. Document and escalate
- Preserve relevant logs.
- Record the evidence and investigation timeline.
- Document confirmed findings separately from assumptions.
- Escalate suspicious activity according to organizational procedures.

## Closure Guidance

Close as benign only when supporting evidence explains the activity.

If suspicious activity remains unexplained, escalate for further investigation.

A detection alert alone does not confirm compromise.
