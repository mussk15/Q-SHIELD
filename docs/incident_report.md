# Q-SHIELD Incident Report Template

## Incident information

- Incident ID:
- Date and time (with timezone):
- Incident type:
- Severity:
- Source IP:
- Affected session:
- Analyst:

## 1. Incident description

Describe what happened and how the monitoring system detected it.

## 2. Detection

- Alert type:
- Detection rule or model:
- Detection timestamp:
- Supporting evidence:

## 3. Impact

Describe the affected service, session or system. Distinguish observed impact from assumptions.

## 4. Containment

- Was the source IP added to the simulated blocklist?
- Was a session-kill request queued?
- Did the server acknowledge and execute the request?
- Was a force-re-key request queued?
- Did the server acknowledge and complete re-keying?

## 5. Evidence

- Evidence log location:
- Hash-chain verification result:
- Related security event IDs:
- Evidence preservation notes:

## 6. Recovery

Describe how normal communication was restored and how this was verified.

## 7. Lessons learned

- What caused the incident?
- What worked?
- What needs improvement?
- Were there false positives or missed detections?

## 8. Conclusion

Summarise the incident and response outcome. Label simulated lab activity as simulated.
