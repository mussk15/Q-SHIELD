# Q-SHIELD Cloud Deployment Guide & Operational Runbook

This guide details the complete cloud deployment architecture, security hardening, container orchestration, and verification procedures for the **Q-SHIELD Post-Quantum Cybersecurity System**.

---

## 1. System Architecture Overview

Q-SHIELD in the cloud is structured as an integrated multi-service system:

```text
+---------------------------------------------------------------------------------+
|                                 INTERNET                                        |
+---------------------------------------------------------------------------------+
        | (HTTPS / 443)                                  | (Raw TCP / 5001)
        v                                                v
+-------------------+                    +----------------------------------------+
|   Caddy Proxy     |                    |        qshield-server                  |
| (Auto TLS/HTTPS)  |                    | (ML-KEM-768 + ML-DSA-65 Secure TCP)    |
+-------------------+                    +----------------------------------------+
        | (HTTP / 8501)                                  |
        v                                                |
+-------------------+                                    |
| qshield-dashboard |                                    |
| (Streamlit 6-Page)|                                    |
+-------------------+                                    |
        |                                                |
        +-------------------+----------------------------+
                            |
                            v
            +-------------------------------+
            |  Shared Persistent Volume     |
            |         (/app/data)           |
            | - events.jsonl                |
            | - sessions.jsonl              |
            | - commands.jsonl              |
            | - command_results.jsonl       |
            | - evidence.jsonl              |
            | - blocklist.json              |
            | - benchmarks.json             |
            +-------------------------------+
```

### Component Breakdown
1. **Public Streamlit Operations Dashboard (`qshield-dashboard`)**:
   - 6 pages: Overview, Threat Alerts, Sessions, Response Centre, Evidence, Cryptographic Benchmarks.
   - Accessible via HTTPS on port 443 (reverse proxied by Caddy).
   - Protected by NIST-aligned memory-hard `scrypt` password hashing and brute-force lockout rate limiting.
2. **Post-Quantum Secure TCP Server (`qshield-server`)**:
   - Persistent daemon listening on port `5001`.
   - Native C `liboqs` (v0.16.0) compiled in-container providing ML-KEM-768 key encapsulation and ML-DSA-65 digital signatures.
   - AES-256-GCM authenticated encryption with HKDF-SHA256 session key derivation.
   - In-band post-quantum re-keying and background response command processor (`kill_session`, `force_rekey`).
   - Automated startup session reconciliation: cleans up orphaned active records from previous runs.
3. **Caddy Reverse Proxy (`caddy`)**:
   - Manages automatic TLS / HTTPS certificates via Let's Encrypt / ZeroSSL.
   - Redirects HTTP (port 80) to HTTPS (port 443).
4. **Remote Secure Client (`qshield.net.secure_client`)**:
   - Runs on external student/analyst machines across the internet.
   - Connects to the cloud server IP/domain over TCP port 5001.

---

## 2. Recommended Cloud Hosting Providers

| Provider | Recommended Architecture | Monthly Cost | Inbound TCP Support | Native C Compilation | Storage Type | Best Suited For |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **DigitalOcean** (Recommended) | Basic Droplet (1 vCPU, 2GB RAM, Ubuntu 24.04) | ~$12/mo (or $4/mo 1GB with swap) | Full raw TCP on port 5001 | Full Docker / GCC support | Persistent SSD volume | Best overall balance of simplicity, fixed IP, and port flexibility. |
| **AWS EC2** | `t4g.small` or `t3.micro` (Free Tier eligible) | $0 (Free Tier) to ~$9/mo | Full raw TCP (Security Group: 5001) | Full Docker support | EBS Persistent Volume | Zero cost during 12-month free tier. |
| **Linode / Akamai** | Shared 2GB Nanode/Linode | $5 - $12/mo | Full raw TCP on port 5001 | Full Docker support | Persistent Block Storage | Highly predictable pricing and performance. |
| **Hetzner Cloud** | CX22 Cloud Server | ~€4/mo | Full raw TCP on port 5001 | Full Docker support | NVMe Persistent SSD | Budget-friendly option for European hosting. |
| **Fly.io** | 2 Apps (Dashboard + Backend) | ~$5/mo | Requires Dedicated IPv4 ($2/mo) | Dockerfile deployment | `fly volumes` | PaaS without managing Linux host OS. |

> [!NOTE]
> Streamlit Community Cloud alone is **insufficient** for Q-SHIELD because it only terminates web traffic on port 8501 and cannot open inbound TCP ports (like 5001) or guarantee persistent file storage for session audits.

---

## 3. Security Hardening Configuration

### 3.1 Generating a Salted Password Hash
Never store plaintext passwords in cloud `.env` files. Generate a memory-hard `scrypt` hash:

```powershell
# Windows
.\.venv\Scripts\python.exe -m scripts.generate_password_hash

# Linux / Cloud Host
python3 -m scripts.generate_password_hash
```

Output format:
```text
scrypt$16384$8$1$1f6ecf11bc9c0aed086df6b2920913ab$1c2f993a8c8aef9af98a13ca26500b30925b4391a42d988a2868859ee75e2a5a
```

Set this in `.env`:
```bash
QSHIELD_DASHBOARD_PASSWORD_HASH=scrypt$16384$8$1$...
```

### 3.2 Linux Firewall (UFW) Hardening
Only expose required ports to the public internet:
```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp    # SSH management
sudo ufw allow 80/tcp    # HTTP (Caddy ACME challenge & redirect)
sudo ufw allow 443/tcp   # HTTPS (Dashboard)
sudo ufw allow 5001/tcp  # Post-Quantum Secure TCP Server
sudo ufw enable
```

### 3.3 Key Material Protection
- Private keystores (`server_private.keystore`) are mounted read-only (`:ro`) into the container.
- Keystores require the password (`QSHIELD_SERVER_PASSWORD`) to decrypt.
- Public keys (`server_public.bin`) are distributed to trusted clients.
- Client identity keys remain exclusively on client machines.

---

## 4. Cloud Deployment Step-by-Step Instructions

### Step 1: Provision a Cloud Linux VM
1. Create an Ubuntu 24.04 LTS instance (e.g. AWS EC2, DigitalOcean Droplet, Linode).
2. Note your public IP address (e.g., `203.0.113.50`).
3. (Optional) Point your DNS A record to this IP (e.g. `qshield.example.com`).

### Step 2: Install Docker & Docker Compose
```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker $USER
```

### Step 3: Clone Repository & Configure Environment
```bash
git clone https://github.com/mussk15/Q-SHIELD.git
cd Q-SHIELD

# Create production .env from template
cp .env.example .env

# Edit .env with your domain and password hash
nano .env
```

Configure in `.env`:
```bash
QSHIELD_DASHBOARD_USERNAME=analyst
QSHIELD_DASHBOARD_PASSWORD_HASH=<your_generated_scrypt_hash>
QSHIELD_SERVER_HOST=0.0.0.0
QSHIELD_SERVER_PORT=5001
QSHIELD_DOMAIN=qshield.example.com   # Or your public IP for direct HTTP/TLS
ACME_EMAIL=admin@example.com
```

### Step 4: Build and Launch Containers
```bash
docker compose up -d --build
```

### Step 5: Verify Deployment Status
```bash
# Check container statuses
docker compose ps

# View real-time logs
docker compose logs -f

# Run automated health check
docker compose exec qshield-server python scripts/health_check.py --server-host 127.0.0.1 --server-port 5001 --dashboard-url http://qshield-dashboard:8501
```

---

## 5. Connecting Remote Clients over the Internet

On any external machine (Windows, Linux, macOS) running Python 3.10+:

1. Clone or copy the Q-SHIELD client package and public keys:
   - `keys/client_private.keystore`
   - `keys/client_public.bin`
   - `keys/server_public.bin`
2. Run the secure client specifying the cloud server address:

```bash
# Connect to cloud server IP or domain
python -m qshield.net.secure_client <CLOUD_IP_OR_DOMAIN> 5001
```

Example session:
```text
Client identity loaded.
Connecting to Q-SHIELD secure server at 203.0.113.50:5001...
Post-quantum handshake successful.
Server identity verified; encrypted session established.
Type messages. Enter /quit to close the session.
You: Hello cloud post-quantum server!
```

---

## 6. Verifying Dashboard Capabilities in Cloud

1. **Access Dashboard**: Open `https://<YOUR_DOMAIN>` (or `http://<IP>:8501`).
2. **Login Verification**:
   - Attempt invalid password -> verifies brute-force counter.
   - Enter authorized credentials -> unlocks 6-page operations console.
3. **Overview**: Confirms `SERVER STATUS: ONLINE (Port 5001)` and displays real-time session counters.
4. **Threat Alerts**:
   - Expand `Offline PCAP / PCAPNG Network Traffic Analysis`.
   - Select `port_scan.pcapng` and click `Run Packet Inspection & IDS Analysis`.
   - Verifies genuine IDS alerts appear in the table.
5. **Sessions**: Confirms actual remote client session ID appears as `Active`.
6. **Response Centre**:
   - Select the active session and click `Queue Server Command` with `Force re-key`.
   - On the client terminal, send a message -> client and server negotiate Generation 1 key in-band.
   - Dashboard table updates to `Gen 1`.
   - Click `Kill session` -> client immediately disconnects and status becomes `Disconnected`.
7. **Evidence**: Confirms SHA-256 hash-chain shows `VALID`.
8. **Cryptographic Benchmarks**: Review live ML-KEM-768 vs ECDH-P256 and ML-DSA-65 vs ECDSA-P256 metrics.

---

## 7. Troubleshooting & Recovery Runbook

| Symptom | Cause | Remedy |
| :--- | :--- | :--- |
| `Connection refused (port 5001)` | Cloud firewall or Security Group blocking port 5001. | Open TCP port 5001 in AWS Security Group / DigitalOcean Cloud Firewall / UFW. |
| `oqs.so: cannot open shared object file` | `liboqs.so` missing from runtime path. | Ensure `LD_LIBRARY_PATH=/usr/local/lib` and `ldconfig` was executed during container build. |
| `InvalidTag` during message decryption | Session keys out of sync or tampering. | Re-run authenticated handshake; check network integrity. |
| Sessions remain "Active" after server crash | Server was abruptly killed without clean shutdown. | Normal behavior before restart: on next server launch, `reconcile_active_sessions()` automatically marks orphaned records as `Disconnected (Server restarted)`. |
| Caddy HTTPS certificate error | DNS record not yet propagated or port 80 blocked. | Ensure ports 80 & 443 are open for ACME challenge and DNS A record points to server IP. |

