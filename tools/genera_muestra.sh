#!/usr/bin/env bash
# genera_muestra.sh — log de prueba con el formato de journalctl -o json.
set -euo pipefail
SALIDA=${1:-/tmp/vigia_muestra.jsonl}
ahora=$(date +%s)
linea() { jq -nc --arg t "$(( ahora - $1 ))000000" --arg m "$2" \
  '{__REALTIME_TIMESTAMP: $t, _COMM: "sshd", MESSAGE: $m}'; }
{
  linea 290 "Accepted password for kali from 10.0.2.20 port 40100 ssh2"
  for i in $(seq 1 14); do
    ip="10.0.2.$(shuf -n1 -e 24 24 24 23 23)"
    user=$(shuf -n1 -e root admin kali test oracle)
    linea $(( 240 - i * 6 )) "Failed password for invalid user $user from $ip port $(( RANDOM + 30000 )) ssh2"
  done
  linea 5 "Accepted password for kali from 10.0.2.23 port 41999 ssh2"
  linea 2 "Failed password for root from 10.0.2.20 port 5555 ssh2"
} > "$SALIDA"
echo "Generado $SALIDA ($(wc -l < "$SALIDA") eventos)"
