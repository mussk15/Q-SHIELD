# Q-SHIELD Incident Response Playbook

## 1. Preparation
- Confirm that the secure server and monitoring modules are running.
- Check that security events are being written to the agreed JSONL format.
- Verify that the dashboard can read the alert feed.
- Use an authorised, isolated lab and synthetic data.

## 2. Detection
- Review incoming security alerts.
- Identify the source IP and any affected session.
- Check alert type, timestamp, severity and supporting evidence.
- Look for repeated suspicious activity and related events.

## 3. Triage
- Identify the affected service or session.
- Review related server and IDS events.
- Determine whether the alert is genuine or a false positive.
- Prioritise Critical and High alerts according to the team's response policy.

## 4. Containment
- Add a suspicious IP to the **simulated** blocklist.
- Queue a kill-session request when appropriate.
- Queue a force-re-key request when appropriate.
- Member 2's server must validate and process session commands.
- Verify server acknowledgement before reporting an action as completed.

## 5. Evidence handling
- Record incident details and response actions.
- Store response audit records in `data/evidence.jsonl`.
- Verify the SHA-256 hash chain.
- Preserve timestamps and relevant event identifiers.
- Do not place passwords, private keys or plaintext secrets in logs.

## 6. Recovery
- Confirm that the server is operating normally.
- Check whether legitimate clients can reconnect.
- Confirm that a new session key was established when re-keying was requested.
- Record the recovery outcome.

## 7. Lessons learned
- Record the cause of the incident.
- Record detection and response times using measured timestamps.
- Identify false positives and missed detections.
- Recommend improvements to monitoring rules and controls.

> This playbook is for a student prototype in an authorised lab. The IP blocklist in this package is simulated and does not alter the operating-system firewall.
