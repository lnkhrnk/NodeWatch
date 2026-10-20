#!/bin/sh
# NodeWatch — центральный сервер (Linux)
cd "$(dirname "$0")"
: "${MON_SECRET:=kursovoy-proekt-2026-secret}"
export MON_SECRET
python3 -m pip install -q -r requirements.txt 2>/dev/null || true
exec python3 server.py "$@"
