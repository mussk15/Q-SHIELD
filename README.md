# Q-SHIELD (Quantum Shield)
**Post-Quantum Secure Communication and Intrusion Detection System**

---

## 1. Project Introduction & Problem Statement

Modern secure communications rely extensively on classical public-key cryptography—principally RSA and Elliptic Curve Cryptography (ECC)—for key exchange and digital signatures. The advent of cryptanalytically relevant quantum computers poses an existential threat to these schemes via Shor's algorithm, enabling retrospective decryption of recorded encrypted traffic ("Store Now, Decrypt Later").

**Q-SHIELD** addresses this vulnerability by deploying NIST-standardized Post-Quantum Cryptography (PQC) algorithms combined with multi-layer network security monitoring and an analyst operations console:
- **ML-KEM-768** (FIPS 203) for quantum-resistant key encapsulation.
- **ML-DSA-65** (FIPS 204) for quantum-resistant mutual identity authentication and digital signatures.
- **HKDF-SHA256** (RFC 5869) for cryptographic session key derivation.
- **AES-256-GCM** for authenticated symmetric payload encryption with integrity guarantees.
- **Dual-Engine Network IDS** combining signature/rule-based detection with unsupervised Machine Learning (Isolation Forest) anomaly detection.
- **Security Operations Console** built on Streamlit with SHA-256 hash-chained evidence recording and server-side command execution.

---

## 2. Team Architecture & Responsibilities

Q-SHIELD is designed and implemented across four collaborative member modules:

### Member 1 — Post-Quantum Cryptography & Anomaly Detection
- Ephemeral ML-KEM-768 key encapsulation and decapsulation (`qshield/crypto/kem.py`).
- ML-DSA-65 digital signature generation and verification (`qshield/crypto/sig.py`).
- HKDF-SHA256 session key derivation (`qshield/crypto/kdf.py`).
- Authenticated AES-256-GCM symmetric encryption with associated data verification (`qshield/crypto/aead.py`).
- Post-quantum mutual handshake state machine (`qshield/net/handshake.py`).
- Secure encrypted keystore with Argon2/PBKDF2-based password protection (`qshield/crypto/keystore.py`).
- Isolation Forest anomaly detection engine (`qshield/monitor/anomaly.py`).

### Member 2 — Secure Networking & File Transfer
- Multi-client TCP server and client implementation (`qshield/net/server.py`, `qshield/net/secure_server.py`, `qshield/net/secure_client.py`).
- Robust length-prefixed message framing with strict size limits (`qshield/net/protocol.py`).
- Authenticated encrypted file transfer with chunk-based AES-256-GCM and SHA-256 integrity verification (`qshield/net/secure_filetransfer.py`).
- Active session tracking, rate limiting, connection limiting, and graceful socket shutdown.
- Server-side command execution engine integrating analyst response actions with active socket sessions.

### Member 3 — Network Monitoring & Intrusion Detection
- Packet sniffing via Scapy for PCAP replay and live network interfaces (`qshield/monitor/sniffer.py`).
- Sliding window traffic feature extraction (`qshield/monitor/features.py`).
- Rule-based detection engine for port scans, SYN floods, brute force, and malformed inputs (`qshield/monitor/rules.py`).
- Integration bridge connecting application events and ML anomaly scoring to alert dispatching (`qshield/monitor/event_bridge.py`, `qshield/monitor/alerts.py`).
- Automated sensor daemon supporting both batch PCAP analysis and continuous event following (`scripts/run_sensor.py`).

### Member 4 — Dashboard, Evidence & Incident Response
- Streamlit security operations console (`dashboard/app.py`).
- Unified monitoring of security alerts, active/historical sessions, and cryptographic benchmarks.
- Incident response interface supporting simulated IP containment and server session command dispatch (`kill_session`, `force_rekey`).
- Append-only response command queue and execution results tracking (`response/commands.py`).
- SHA-256 hash-chained auditable evidence logging (`response/evidence.py`).
- Simulated application-level IP blocklist management (`response/blocklist.py`).

---

## 3. System Workflows

### 3.1 Post-Quantum Cryptographic Handshake
```
Client                                                   Server
  |                                                        |
  |<-------------- ServerHello ----------------------------|  [Ephemeral ML-KEM PK, Server Nonce,
  |   (Verified with Trusted Server ML-DSA Public Key)     |   ML-DSA Signature over Hello]
  |                                                        |
  |--------------- ClientFinish -------------------------->|  [ML-KEM Ciphertext, Client Nonce,
  |   (Signed with Client ML-DSA Private Key)              |   Client ML-DSA PK, Signature]
  |                                                        |  [Server verifies Client ML-DSA PK,
  |                                                        |   decapsulates ML-KEM shared secret,
  |                                                        |   derives Key via HKDF-SHA256]
  |<-------------- ServerFinish ---------------------------|  [Server transcript HMAC verification]
  |                                                        |
  +========== Established AES-256-GCM Secure Channel ======+
```

### 3.2 Secure File Transfer
1. Sender verifies source file, validates `file_size <= 100 MB`, and computes overall SHA-256 digest.
2. Metadata header `{"filename", "size", "sha256", "chunk_size", "chunk_count"}` is transmitted.
3. Receiver validates filename against path traversal (`/`, `\`, `..`, null bytes) and checks for duplicate destination files.
4. File is split into 64 KB chunks, each encrypted under AES-256-GCM with associated authenticated data (AAD) binding chunk index and file metadata.
5. Receiver decrypts each chunk, verifies authentication tag, computes cumulative SHA-256 hash, and atomic-renames the temporary staging file upon full verification.

### 3.3 Intrusion Detection System (IDS)
- **Traffic Feature Extraction**: Packets are grouped into rolling 10-second sliding windows per source IP, extracting 12 numerical features: `packet_count`, `connection_attempts`, `syn_count`, `syn_ack_count`, `rst_count`, `half_open_syns`, `failed_handshakes`, `distinct_dst_ports`, `distinct_dst_ips`, `bytes_total`, `message_rate`.
- **Rule Engine**: Evaluates feature windows against thresholds in `config/thresholds.yaml` to detect Port Scans (`PORT_SCAN`) and SYN Floods (`SYN_FLOOD`).
- **ML Anomaly Detection**: Passes feature vectors to an Isolation Forest model (`data/anomaly_model.joblib`) to identify statistical outliers without requiring signatures.
- **Application Event Bridge**: Evaluates application-level security events (handshake failures, authentication tag errors, replay attempts) and emits security alerts into `data/alerts.jsonl`.

### 3.4 Incident Response & Command Execution
1. Analyst inspects an active session on the Streamlit **Response** tab.
2. Submitting a `kill_session` command queues an append-only JSON record in `data/commands.jsonl`.
3. The server's background `command_processor` reads the queue, validates the command ID, and matches the session ID in `active_sessions`.
4. The server terminates the corresponding client socket safely (`shutdown` + `close`) and transitions the session state to `Disconnected`.
5. The execution result (`executed`, `already_disconnected`, or `rejected`) is recorded in `data/command_results.jsonl`.
6. The action is recorded with a cryptographic hash in `data/evidence.jsonl`, and the dashboard updates in real time.

### 3.5 Authenticated In-Band Post-Quantum Re-Keying
1. When an analyst submits `force_rekey` for an active session, the command is recorded in `data/commands.jsonl` and acknowledged as `queued`.
2. The secure server queues the re-key request (`enqueue_rekey_request`) for delivery at the next client message boundary.
3. Upon receiving the client's next application message, the server initiates the 4-way post-quantum re-key protocol:
   - **`QSHIELD_REKEY_OFFER`**: Ephemeral ML-KEM-768 public key, previous-key hash, generation number, and ML-DSA-65 signature.
   - **`QSHIELD_REKEY_RESPONSE`**: Client encapsulates fresh KEM secret, attaches client nonce, and signs with client ML-DSA-65 identity.
   - **`QSHIELD_REKEY_FINISHED`**: Both derive the replacement AES-256-GCM key using HKDF-SHA256 (mixing old session key, new KEM secret, and transcript hash). Server confirms with Finished MAC.
   - **`QSHIELD_REKEY_COMMIT`**: Client verifies server Finished MAC, confirms new key with Commit MAC, and switches keys.
4. Server verifies client Commit MAC and atomically switches session key, incrementing the key generation.
5. Server records `executed` in `data/command_results.jsonl` and logs `SESSION_REKEY_SUCCESS` in `data/events.jsonl`.
6. All subsequent application messages are encrypted and decrypted using the new generation key; prior keys are immediately invalidated.

---

## 4. Installation & Windows Setup

### 4.1 Prerequisites
- Windows 10/11 (64-bit)
- Python 3.10+ (tested with Python 3.12 and 3.14)
- PowerShell 5.1+ or PowerShell 7+
- Native `liboqs.dll` (Open Quantum Safe native library)

### 4.2 Virtual Environment Setup
Open Windows PowerShell inside `C:\Q-SHIELD`:

```powershell
# Create virtual environment (if not already created)
python -m venv .venv

# Activate virtual environment
.\.venv\Scripts\Activate.ps1

# Upgrade pip and install dependencies
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### 4.3 Native Cryptographic Library Setup
Q-SHIELD utilizes `liboqs-python` backed by the native `oqs.dll` build containing ML-KEM and ML-DSA implementations.

Ensure `oqs.dll` is available in either `C:\liboqs\build\bin\Release` or `C:\Users\PC\_oqs\bin`:
```powershell
# Set OQS_INSTALL_PATH environment variable (optional, backend auto-discovers candidate paths)
$env:OQS_INSTALL_PATH = "$HOME\_oqs"
$env:PATH = "C:\liboqs\build\bin\Release;$env:PATH"
```

### 4.4 Dashboard Configuration
Create and configure your local `.env` file:
```powershell
# Create .env from example
Copy-Item .env.example .env
```
Edit `.env` to set your dashboard credentials and data directory:
```ini
QSHIELD_DASHBOARD_USERNAME=analyst
QSHIELD_DASHBOARD_PASSWORD=YourStrongPasswordHere!
QSHIELD_DATA_DIR=data
```

---

## 5. Execution Instructions

### 5.1 Running the Secure TCP Server
Starts the post-quantum secure server listening on port 5001 with active command processing:
```powershell
.\.venv\Scripts\Activate.ps1
python qshield\net\secure_server.py
```

### 5.2 Running the Secure Client
Connects to the secure server, performs post-quantum mutual authentication, and opens an encrypted messaging session:
```powershell
.\.venv\Scripts\Activate.ps1
python qshield\net\secure_client.py
```

### 5.3 Running Secure Encrypted File Transfer
Send an encrypted file with post-quantum session authentication:
```powershell
# Terminal 1: File Receiver Server (Listening on port 5002)
python qshield\net\secure_file_server.py

# Terminal 2: File Sender Client
python qshield\net\secure_file_client.py --file data\test_files\sample.bin
```

### 5.4 Running the IDS Sensor
Replay an existing PCAP attack capture or monitor live network traffic:
```powershell
# Replay captured PCAP traffic through IDS feature extractor & ML detector
python scripts\run_sensor.py --pcap data\port_scan.pcapng

# Or follow live application events continuously
python scripts\run_sensor.py --follow-events
```

### 5.5 Running the Streamlit Quantum Security Operations Dashboard
```powershell
python -m streamlit run dashboard\app.py --server.port 8502
```
Navigate to `http://localhost:8502` and log in with your credentials (`analyst` / configured password).

The unified dashboard provides 10 interconnected operational interfaces without needing separate terminals:
1. **Overview**: Executive KPI metrics, recent activity feed, threat severity distribution, and interactive architecture diagrams.
2. **Server Control**: Start, stop, and monitor the post-quantum TCP server (port 5001), inspect port conflicts, and manage active sessions.
3. **Client Console**: Connect client using ML-KEM-768/ML-DSA-65 handshake, exchange AES-256-GCM encrypted messages, and view real-time server replies.
4. **File Transfer**: AES-256-GCM chunked encrypted file transfer, automatic file receiver management (port 5002), SHA-256 integrity verification, and browser for `data/received_files/`.
5. **Network Monitoring**: PCAP packet inspection (`normal.pcapng`, `port_scan.pcapng` or upload) through feature extractor and IDS, live Scapy packet sniffing, and network interface inspector.
6. **Threats & Alerts**: Unified view of rule-based and Isolation Forest alerts, severity filtering, search, and full alert details.
7. **Sessions**: Active socket sessions, disconnected session archive, re-key generation counters, and cryptographic lifecycle details.
8. **Incident Response**: Analyst containment console with `force_rekey`, `kill_session`, simulated IP blocklist, and live command result tracking.
9. **Evidence & Audit**: Cryptographic SHA-256 hash-chain verification tool (`verify_chain`) ensuring tamper-evident audit records in `data/evidence.jsonl`.
10. **Benchmarks & System Status**: NIST PQC vs classical ECDH/ECDSA benchmark timings and key sizes, subsystem health diagnostics, and threshold configuration.

---

---

## 6. Cryptographic Benchmarks

Benchmark post-quantum operations against classical NIST P-256 baselines:
```powershell
# Run benchmark and output to data/benchmarks.json
.\benchmarks\run_benchmarks.bat

# Or run directly via Python:
python -m benchmarks.bench_pq_vs_classic --iterations 20 --output data/benchmarks.json
```
The generated `data/benchmarks.json` is displayed on the Streamlit dashboard **Benchmarks** tab, reporting real measured timings (`keygen_ms`, `encaps_ms`, `decaps_ms`, `sign_ms`, `verify_ms`) and public/secret key and signature byte sizes for ML-KEM-768, ECDH-P256, ML-DSA-65, and ECDSA-P256.

---

## 7. Testing & Validation

Run the complete automated test suite (unit, functional, security, and end-to-end integration):
```powershell
.\.venv\Scripts\Activate.ps1
python -m pytest -v
```

Run the live interactive re-key verification script:
```powershell
python scripts/verify_live_rekey.py
```

### Test Suite Breakdown (114 Tests Total - 100% Passing):
- `tests/test_kem.py`: ML-KEM-768 encapsulation, decapsulation, invalid key rejection (4 tests)
- `tests/test_sig.py`: ML-DSA-65 signing, verification, tampering rejection (6 tests)
- `tests/test_kdf.py`: HKDF-SHA256 deterministic key derivation and context separation (6 tests)
- `tests/test_aead.py`: AES-256-GCM round trip, AAD authentication, tampering detection (4 tests)
- `tests/test_handshake.py`: Post-quantum mutual handshake state machine and replay rejection (4 tests)
- `tests/test_rekey.py`: Authenticated in-band post-quantum re-keying, MAC checks, queueing (9 tests)
- `tests/test_keystore.py`: Encrypted private-key storage with password protection (4 tests)
- `tests/test_protocol.py`: Length-prefixed framing, fragmentation, invalid UTF-8 (7 tests)
- `tests/test_server.py`: Connection timeout, socket management, slot release (1 test)
- `tests/test_commands.py`: Response command queueing, concurrency, kill_session execution, rekey queueing and rejection (12 tests)
- `tests/test_filetransfer.py`: Classical file transfer and duplicate prevention (4 tests)
- `tests/test_secure_filetransfer.py`: AES-GCM chunked file transfer, SHA-256 integrity, path traversal (7 tests)
- `tests/test_features.py`: Network feature windowing and pruning (2 tests)
- `tests/test_rules.py`: IDS rule evaluation for port scans and SYN floods (6 tests)
- `tests/test_anomaly.py`: Isolation Forest model training, inference, and evaluation (5 tests)
- `tests/test_attack_labs.py`: Replay guard, tampering lab, fail-closed cache (4 tests)
- `tests/test_blocklist.py`: IP blocklist validation, duplicate prevention (3 tests)
- `tests/test_evidence.py`: SHA-256 hash-chain verification and tampering detection (3 tests)
- `tests/test_event_logging.py`: Security event logging format and thread safety (4 tests)
- `tests/test_crypto_backend.py`: OQS backend algorithm verification (2 tests)
- `tests/test_benchmark.py`: Cryptographic algorithm benchmarking smoke tests (2 tests)
- `tests/test_dashboard.py`: Streamlit dashboard headless page rendering across all 10 unified views (6 tests)
- `tests/test_services.py`: Managed Server, Client, File Transfer, Monitor, and ServiceManager services (7 tests)
- `tests/test_e2e_integration.py`: Complete End-to-End integration across all subsystems, including full rekey workflow (2 tests)

---

## 8. Known Limitations & Architectural Notes

1. **Simulated IP Containment**: IP blocking in the dashboard is an application-level filter maintained in `data/blocklist.json` and checked by the TCP servers; it does not install operating system firewall (`netsh advfirewall` or `iptables`) rules.
2. **Message-Boundary Re-Key Delivery**: In-band authenticated re-keying operates at the application message boundary. When an analyst submits `force_rekey`, the server queues the request; when the client sends its next message, the server initiates the 4-way exchange, switches keys, and delivers the application reply under the new key.
3. **ML Anomaly Detection Sample Size Requirements**:
   - The initial capture dataset (`data/labelled_windows.csv`) contained 17 normal windows from an 11-second capture, producing zero precision/recall due to lack of sample variance.
   - When trained on a representative controlled lab dataset (`data/lab_labelled_windows.csv`), the Isolation Forest detector achieves **90.9% precision and 100.0% recall** (F1 = 0.952).
4. **Lab Prototype Scope**: This project is developed for educational and demonstration purposes in an authorized lab environment; it is not audited for high-assurance production deployment.
