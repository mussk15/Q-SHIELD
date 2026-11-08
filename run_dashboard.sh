#!/usr/bin/env bash
set -euo pipefail
python -m streamlit run dashboard/app.py --server.port 8502
