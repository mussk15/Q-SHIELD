# Q-SHIELD Testing and Validation Report

Record actual results. Do not mark a test as passed until it has been executed and evidence has been captured.

## Test case table

| ID | Test | Expected result | Actual result | Status | Evidence/reference |
|---|---|---|---|---|---|
| T1 | ML-KEM encapsulation and decapsulation | Both sides derive the same shared secret | | | |
| T2 | Wrong KEM key or altered ciphertext | Rejected safely; no crash | | | |
| T3 | ML-DSA signature verification | Valid signature accepted; invalid rejected | | | |
| T4 | Forged server signature | Client aborts and event is logged | | | |
| T5 | Unregistered client | Authentication rejected and logged | | | |
| T6 | Modified encrypted record | GCM authentication failure | | | |
| T7 | Replayed message | Old sequence rejected and logged | | | |
| T8 | Oversized frame or invalid JSON | Safely rejected; server remains available | | | |
| T9 | Nonce reuse prevention | Nonces do not repeat under the same key | | | |
| T10 | Port scan against own lab server | Scan alert generated | | | |
| T11 | Low-rate connection flood against own lab server | Flood alert generated; service remains responsive | | | |
| T12 | Repeated failed handshakes | Brute-force alert generated | | | |
| T13 | Normal chat/file transfer for five minutes | No unexpected alerts | | | |
| T14 | Evidence log modification | Hash-chain verification fails | | | |
| T15 | Fresh installation using README | Project starts successfully | | | |

## Detection evaluation

| Metric | Rules only | ML model only | Combined |
|---|---:|---:|---:|
| Precision | | | |
| Recall | | | |
| F1 score | | | |
| False-positive rate | | | |
| Time to detect | | | |

## Findings

Describe executed tests, observed errors, false positives, missed detections and the evidence used to confirm results.

## Limitations

State that this is a student prototype tested in an authorised lab using synthetic or controlled data. Report actual library choices and measured results.

## Conclusion

Summarise the measured results and list unresolved defects.
