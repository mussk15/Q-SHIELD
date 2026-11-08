# Q-SHIELD

Quantum-Safe Secure Communication and Intrusion Detection System

Project Overview

Q-SHIELD is a cybersecurity project that aims to provide secure communication using post-quantum cryptography and detect suspicious network activities using an Intrusion Detection System (IDS).

Objectives

* Establish secure communication using post-quantum cryptography.
* Encrypt messages using AES-256-GCM.
* Authenticate users and verify digital signatures.
* Detect suspicious network activities.
* Generate security alerts and maintain event logs.

Technologies Used

* Python
* ML-KEM
* ML-DSA
* AES-256-GCM
* TCP Sockets
* Scapy
* Streamlit
* Git and GitHub

Team Members

Details to be added.

Project Status

Development in progress.

How to Run

Instructions will be added after implementation.
## Member 4 – Dashboard and Incident Response



The Q-SHIELD Streamlit dashboard provides a centralized interface for security monitoring and incident response.



\### Features

\- Security overview and dashboard metrics

\- IDS alert monitoring

\- Secure session monitoring

\- Simulated IP blocklist management

\- Kill-session and force-re-key command queues

\- SHA-256 hash-chained evidence logging

\- Cryptographic benchmark display



\### Windows Setup



Create and activate a virtual environment:



```cmd

py -m venv .venv

.venv\\Scripts\\activate.bat

```



Install dependencies:



```cmd

python -m pip install --upgrade pip

python -m pip install -r requirements.txt

```



Configure the dashboard:



```cmd

copy .env.example .env

```



Edit `.env` and set your own dashboard password.



Generate synthetic demonstration data:



```cmd

python scripts\\create\_demo\_data.py

```



Run tests:



```cmd

python -m pytest -q

```



Start the dashboard:



```cmd

python -m streamlit run dashboard\\app.py --server.port 8502

```



Open `http://localhost:8502` in your browser.



\### Implementation Limitations

\- IP blocking is simulated and does not modify the operating system firewall.

\- Session termination and re-key requests require server-side processing and acknowledgement.

\- Synthetic records are for demonstration only.

\- This project is an educational cybersecurity prototype, not production-audited software.