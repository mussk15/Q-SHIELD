# Q-SHIELD Member 4 Integration Contract

The dashboard reads the following local files from the configured data directory. The team should freeze these field names before merging all modules.

## 1. `events.jsonl` — owner: Member 2

One JSON object per line. Example:

```json
{"timestamp":"2026-11-07T10:00:00Z","event_type":"handshake_success","outcome":"success","source_ip":"127.0.0.1","session_id":"session-001","bytes":320}
```

Do not log passwords, private keys, shared secrets or plaintext message contents.

## 2. `alerts.jsonl` — owner: Member 3

One JSON object per line. Example:

```json
{"id":"alert-001","timestamp":"2026-11-07T10:01:00Z","type":"Port Scan","source_ip":"192.0.2.10","severity":"MEDIUM","evidence":"Multiple destination ports observed","status":"Open"}
```

Severity values: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.

## 3. `sessions.jsonl` — owner: Member 2

One JSON object per line. Example:

```json
{"session_id":"session-001","user_id":"alice","remote_ip":"127.0.0.1","status":"Active","started_at":"2026-11-07T10:00:00Z","key_fingerprint":"sha256:example"}
```

Never expose session keys. A key fingerprint is informational metadata only.

## 4. `blocklist.json` — dashboard helper owned by Member 4

Contains simulated blocked IP addresses. Member 2 must explicitly check this blocklist when accepting connections if the team chooses this integration design. The helper does not modify Windows Firewall.

## 5. `commands.jsonl` — produced by Member 4, consumed by Member 2

Supported values:
- `kill_session`
- `force_rekey`

Each queued record contains a unique `command_id`, timestamp, command, session ID, actor, reason and `status: queued`. Member 2 must validate the command, execute it, prevent duplicate execution and write an acknowledgement/result. A queued command is not proof of execution.

## 6. `evidence.jsonl` — maintained by Member 4

Contains response audit records chained with SHA-256. This is tamper-evident only when compared with a trusted checkpoint; it is not a digital signature or immutable storage.

## 7. `benchmarks.json` — owner: Member 1

Example shape:

```json
[
  {
    "algorithm": "ML-KEM-768",
    "keygen_ms": 1.5,
    "encaps_ms": 1.2,
    "decaps_ms": 1.1,
    "public_key_bytes": 1184,
    "ciphertext_bytes": 1088
  }
]
```

Illustrative values must be replaced with actual measurements from Member 1. Do not present example timings as measured results.
