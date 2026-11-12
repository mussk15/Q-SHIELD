# Q-SHIELD Testing and Validation Report

This report documents verified test results from the automated test suite and integration runs executed on Windows with native liboqs (`oqs.dll`).

## 1. Test Case Table

| ID | Test | Expected result | Actual result | Status | Evidence / Reference |
|---|---|---|---|---|---|
| T1 | ML-KEM-768 encapsulation / decapsulation round trip | Both sides derive the identical 32-byte shared secret | Decapsulated secret matches encapsulated secret exactly | PASS | `tests/test_kem.py::test_ml_kem_768_encapsulation_round_trip` |
| T2 | Altered KEM ciphertext or wrong length | Rejected safely with `ValueError` or decapsulation error | Rejected cleanly without crash or secret leakage | PASS | `tests/test_kem.py::test_encapsulate_rejects_wrong_public_key_length`, `test_decapsulate_rejects_empty_inputs` |
| T3 | ML-DSA-65 digital signature round trip | Valid signature accepted; altered message/signature rejected | Signature verified successfully; tampered message and altered signature return `False` | PASS | `tests/test_sig.py::test_ml_dsa_65_sign_and_verify_round_trip`, `test_modified_message_fails_verification` |
| T4 | Forged server handshake hello | Client rejects modified `ServerHello` signature | HandshakeError raised: "Server identity signature is invalid" | PASS | `tests/test_handshake.py::test_client_rejects_modified_server_hello` |
| T5 | Untrusted client identity key | Server rejects untrusted client public key | HandshakeError raised: "Client identity key does not match the trusted key" | PASS | `tests/test_handshake.py::test_server_rejects_untrusted_client_identity` |
| T6 | AES-256-GCM ciphertext or AAD tampering | Cryptography `InvalidTag` raised; decryption aborts | Detected tampering immediately; `InvalidTag` raised, no plaintext returned | PASS | `tests/test_aead.py::test_aes_gcm_detects_ciphertext_tampering`, `test_aes_gcm_authenticates_associated_data` |
| T7 | Message replay guard | Repeated cryptographic handshake states or messages rejected | Handshake state marked consumed; duplicate replay throws `HandshakeError` | PASS | `tests/test_handshake.py::test_server_handshake_state_cannot_be_replayed`, `tests/test_attack_labs.py` |
| T8 | Oversized message framing and invalid UTF-8 | Enforces `MAX_MESSAGE_SIZE` (1 MB) and rejects invalid UTF-8 | `ValueError` raised on oversized messages; UnicodeDecodeError caught safely | PASS | `tests/test_protocol.py::TestProtocol::test_large_message_rejected`, `test_invalid_utf8_rejected` |
| T9 | Nonce handling under AES-GCM | Fresh random 12-byte nonce per message; distinct nonces | Nonces are randomly generated via `secrets.token_bytes(12)` per encryption | PASS | `qshield/crypto/aead.py`, `tests/test_aead.py` |
| T10 | Network IDS: Port scan detection | High distinct destination ports trigger `PORT_SCAN` alert | `RuleEngine` emits `PORT_SCAN` alert (score 80, severity HIGH) to `alerts.jsonl` | PASS | `tests/test_rules.py::test_port_scan_rule`, `scripts/run_sensor.py` |
| T11 | Network IDS: SYN flood detection | High volume unmatched SYNs trigger `SYN_FLOOD` alert | `RuleEngine` emits `SYN_FLOOD` alert (score 95, severity CRITICAL) | PASS | `tests/test_rules.py::test_syn_flood_rule` |
| T12 | Network IDS: Repeated authentication failures | Cumulative failures exceed threshold within 5-minute window | `AUTH_FAILURE` alert emitted with source IP tracking | PASS | `tests/test_rules.py::test_auth_failure_requires_threshold` |
| T13 | Secure encrypted file transfer | AES-GCM chunked transfer + SHA-256 integrity verification | Multi-chunk files transferred, verified, and saved; duplicate & path-traversal rejected | PASS | `tests/test_secure_filetransfer.py` (7/7 tests passed) |
| T14 | Evidence log hash chain verification | Modifying any entry in `evidence.jsonl` causes hash mismatch | Altering record payload causes `verify_chain` to return `False` with exact sequence mismatch | PASS | `tests/test_evidence.py::test_modified_record_fails_verification` |
| T15 | Server-side command execution (`kill_session`) | Closes target socket, writes acknowledgment to `command_results.jsonl` | Active socket closed; client receives EOF; acknowledgment status `"executed"` | PASS | `tests/test_commands.py::test_kill_session_terminates_active_socket` |
| T16 | In-session re-key command handling (`force_rekey`) | Validates active session, enqueues request, acknowledges `queued`; rejects inactive and duplicate requests | Acknowledged as `queued` for active sessions; `rejected` for inactive/duplicates | PASS | `tests/test_commands.py::test_force_rekey_queued_acknowledgement`, `test_force_rekey_inactive_session_rejected`, `test_force_rekey_duplicate_request_rejected` |
| T17 | Authenticated in-band post-quantum re-key protocol | Ephemeral ML-KEM-768 offer signed with ML-DSA-65, client response, Finished/Commit MAC confirmations | Both endpoints derive and confirm identical replacement key; tampered/replayed offers rejected | PASS | `tests/test_rekey.py` (9/9 tests passed) |
| T18 | Complete End-to-End integration workflow | Demonstrates handshake, messaging, file transfer, IDS alerts, command execution, and shutdown | Client/server PQ handshake, encrypted echo, file transfer, IDS alert, kill command execution verified | PASS | `tests/test_e2e_integration.py::test_complete_qshield_e2e_workflow` |
| T19 | End-to-End in-band re-key integration workflow | Validates handshake, message boundary rekeying, generation 1 key derivation, acknowledgement, old-key rejection | Both sides agree on gen 1 key; status `executed` logged; old key fails tag verification | PASS | `tests/test_e2e_integration.py::test_complete_qshield_e2e_rekey_workflow`, `scripts/verify_live_rekey.py` |
| T20 | Streamlit dashboard headless validation | Dashboard pages load without unhandled layout or rendering exceptions | Overview, Threat Alerts, Sessions, Response Centre, Evidence, Cryptographic Benchmarks render cleanly | PASS | `tests/test_dashboard.py` (6/6 tests passed) |

---

## 2. Detection Evaluation

### A. Original PCAP Dataset (`data/labelled_windows.csv`)
- **Source**: 17 normal windows (from 11.9s `normal.pcapng`), 21 attack windows (from `port_scan.pcapng`).
- **Training/Testing Split**: 11 training normal windows / 6 held-out normal windows + 21 attack windows.
- **Observed Metrics**:
  - Precision: `0.000`
  - Recall: `0.000`
  - F1-Score: `0.000`
  - Confusion Matrix: `TP=0, FP=1, TN=5, FN=21`
- **Root Cause Analysis**:
  1. *Extreme Sample Scarcity*: Isolation Forest requires adequate sample depth (default `max_samples=256`). With only 11 training samples, tree depth is capped at 4.
  2. *Zero Feature Variance*: 6 of the 12 features in normal training rows had zero variance (`connection_attempts=0`, `syn_count=0`, etc.).
  3. *Threshold Skew*: One normal sample (`10.42.45.61`) had `distinct_dst_ips=4` which created a heavy outlier score of `-0.761`. On 11 samples with `contamination=0.05`, `offset_` was set to `-0.6737`.
  4. All 21 attack windows had scores between `-0.604` and `-0.662` (greater than `-0.6737`), resulting in positive decision function values and `predict() = 1` (normal).

### B. Controlled Lab Dataset (`data/lab_labelled_windows.csv`)
- **Source**: 50 synthetic baseline windows with realistic benign query variance, 15 port scan windows, 15 SYN flood windows.
- **Training/Testing Split**: 35 training normal windows / 15 held-out normal windows + 30 attack windows.
- **Observed Metrics**:
  - Precision: `0.909` (90.9%)
  - Recall: `1.000` (100.0%)
  - F1-Score: `0.952` (95.2%)
  - Confusion Matrix: `TP=30, FP=3, TN=12, FN=0`

---

## 3. Summary of Test Execution

- **Total Automated Test Cases Executed**: 107 unit, functional, security, and integration tests
- **Tests Passed**: 107 (100%)
- **Tests Failed**: 0 (0%)
- **Tests Skipped**: 0 (0%)
- **Live Integration Verification**: 11/11 phases passed via `scripts/verify_live_rekey.py`
- **Native Post-Quantum Backend**: liboqs 0.16.0 (`oqs.dll`), liboqs-python 0.16.0.2 (0 warnings)
- **Cryptographic Benchmarks**: Generated via `benchmarks/run_benchmarks.bat` into `data/benchmarks.json`

