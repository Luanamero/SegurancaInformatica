#!/bin/bash
# ============================================================
# start.sh — Inicia ambas as aplicações Flask
# ============================================================
ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo ""
echo "  ╔══════════════════════════════════════════╗"
echo "  ║   SQL Injection Demo — Arranque          ║"
echo "  ╚══════════════════════════════════════════╝"
echo ""

if ! command -v python3 &> /dev/null; then
    echo "   Python3 não encontrado. Instale Python 3.8+"
    exit 1
fi
if ! python3 -c "import flask" 2>/dev/null; then
    echo "    A instalar dependências..."
    pip install -r "$ROOT_DIR/requirements.txt"
fi

echo "  [1/3] Base de dados..."
python3 "$ROOT_DIR/database/init_db.py"
echo ""

echo "  [2/3] A iniciar app VULNERÁVEL (porta 5001)..."
python3 "$ROOT_DIR/app_vulneravel/app.py" > "$ROOT_DIR/vuln.log" 2>&1 &
PID_VULN=$!
sleep 1

echo "  [3/3] A iniciar app SEGURA (porta 5002)..."
python3 "$ROOT_DIR/app_segura/app.py" > "$ROOT_DIR/safe.log" 2>&1 &
PID_SAFE=$!
sleep 1

echo ""
echo "   Ambas as apps estão a correr!"
echo ""
echo "    App Vulnerável : http://localhost:5001"
echo "    App Segura     : http://localhost:5002"
echo ""
echo "  Pressiona Ctrl+C para parar ambos os servidores."
echo ""

trap "echo ''; echo '  A parar servidores...'; kill $PID_VULN $PID_SAFE 2>/dev/null; echo '  Pronto.'; exit 0" SIGINT SIGTERM
wait
