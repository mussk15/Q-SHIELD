#!/usr/bin/env bash
# Authorised loopback-only scan demonstration. Requires Nmap.
set -euo pipefail
TARGET="127.0.0.1"
echo "[Q-SHIELD LAB] Scanning only ${TARGET}, ports 8000-8015"
nmap -sT -Pn -p 8000-8015 --reason "${TARGET}"
