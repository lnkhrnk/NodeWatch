#!/bin/sh
# NodeWatch — агент (Linux). Использование: ./start-agent.sh IP_СЕРВЕРА [ИМЯ_УЗЛА]
cd "$(dirname "$0")"
: "${MON_SECRET:=kursovoy-proekt-2026-secret}"
export MON_SECRET
SERVER="${1:-127.0.0.1}"
python3 -m pip install -q -r requirements.txt 2>/dev/null || true
if [ -n "$2" ]; then exec python3 agent.py --host "$SERVER" --node "$2"; fi
exec python3 agent.py --host "$SERVER"
