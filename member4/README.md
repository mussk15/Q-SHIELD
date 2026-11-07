# Q-SHIELD — Member 4 Package

**Role:** Dashboard, Response, Testing and Presentation  
**Project:** Quantum Shield — Post-Quantum Secure Communication and Intrusion Detection System

This folder is a self-contained Member 4 starter package. It is designed to be copied into the team's central Q-SHIELD repository after the team agrees on the integration contract.

## Included

- Streamlit dashboard: Overview, Alerts, Sessions, Response, Evidence and Benchmarks
- Simulated IP blocklist helper
- Append-only command queue for Member 2's server to consume
- SHA-256 hash-chained evidence log
- Synthetic dashboard preview data generator
- Nine unit tests for the response helpers
- Incident response playbook, incident report template, T1–T15 validation template, integration contract, slide outline and demo script

## Requirements

- Python 3.11 or newer (the dashboard dependencies should also be checked on the team's chosen Python version)
- Windows, Linux or macOS
- Internet access for installing packages; the dashboard itself reads local files

## Windows setup (Command Prompt)

Open Command Prompt in the extracted `Q-SHIELD_Member4` folder.

```cmd
py --version
py -m venv .venv
.venv\Scripts\activate.bat
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Create the local environment file:

```cmd
copy .env.example .env
notepad .env
```

Set your own dashboard password in `.env`:

```text
QSHIELD_DASHBOARD_USERNAME=analyst
QSHIELD_DASHBOARD_PASSWORD=replace-with-your-own-strong-password
QSHIELD_DATA_DIR=data
```

Change the example password before starting the dashboard. Do not commit `.env`.

Generate synthetic preview records:

```cmd
python scripts\create_demo_data.py
```

Run unit tests:

```cmd
python -m pytest -q
```

Launch the dashboard:

```cmd
python -m streamlit run dashboard\app.py --server.port 8502
```

Open `http://localhost:8502` in your browser. Login with username `analyst` and the password you configured in `.env`.

## Existing Q-SHIELD project

This ZIP contains one top-level folder named `Q-SHIELD_Member4`. Extract it to a location of your choice. For integration into the team's repository, copy its `dashboard`, `response`, `scripts`, `tests`, `docs` and configuration files into the central repository after agreeing on any conflicting files. Do not replace the team's existing `requirements.txt`, README or project structure without coordinating with Member 2.

## Data contract

See `docs/integration_contract.md`. The dashboard expects:

- `data/events.jsonl` — server/security events from Member 2
- `data/alerts.jsonl` — IDS alerts from Member 3
- `data/sessions.jsonl` — session metadata from Member 2
- `data/benchmarks.json` — measured benchmark results from Member 1
- `data/blocklist.json` — simulated IP blocklist maintained by this package
- `data/commands.jsonl` — response commands queued by this dashboard for Member 2
- `data/evidence.jsonl` — local hash-chained evidence records

The JSONL files use one JSON object per line.

## Important limitations

1. The IP blocklist is simulated. It does not configure Windows Firewall, Linux nftables/iptables or a production firewall.
2. `kill_session` and `force_rekey` are queued requests. Member 2 must implement a safe server-side consumer, validation, duplicate prevention and acknowledgements before these actions occur.
3. The evidence hash chain is tamper-evident, not tamper-proof. A trusted external checkpoint or protected storage is needed to resist complete chain rewriting.
4. Dashboard login is a classroom demonstration, not production authentication or authorisation.
5. Preview records are synthetic. Do not report them as real attack observations, actual benchmarks or measured IDS performance.
6. This package is not audited production security software.

## Folder structure

```text
Q-SHIELD_Member4/
├── dashboard/
│   ├── __init__.py
│   └── app.py
├── response/
│   ├── __init__.py
│   ├── blocklist.py
│   ├── commands.py
│   ├── evidence.py
│   └── playbook.md
├── scripts/
│   └── create_demo_data.py
├── tests/
│   ├── __init__.py
│   ├── test_blocklist.py
│   ├── test_commands.py
│   └── test_evidence.py
├── docs/
├── data/
├── .env.example
├── .gitignore
├── requirements.txt
└── README.md
```
