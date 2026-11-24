#!/usr/bin/env bash
# ver_ataques.sh — visor del log del honeypot. Sin argumentos: histórico.
# Con -f: sigue el fichero en vivo (espera a que aparezca si aún no existe).
set -euo pipefail
LOG=${VIGIA_HONEYPOT_LOG:-/var/log/ssh_honeypot.jsonl}
# No se crea el fichero aquí: si lo creara este script, nacería con permisos 644
# y el honeypot escribiría contraseñas en un fichero legible por todos.
if [[ -e $LOG && ! -r $LOG ]]; then echo "sin permisos sobre $LOG (usa sudo)"; exit 1; fi
python3 - "$LOG" "${1:-}" <<'PY'
import json
import os
import sys
import time

ruta = sys.argv[1]
seguir = len(sys.argv) > 2 and sys.argv[2] == "-f"
C = {"baja": "\033[36m", "media": "\033[33m", "alta": "\033[91m", "critica": "\033[1;91m"}
R, B, D = "\033[0m", "\033[1m", "\033[2m"
tot = {"baja": 0, "media": 0, "alta": 0, "critica": 0}
usuarios, contrasenas, ips = {}, {}, {}


def visible(valor, ancho=None):
    """Lo que manda el atacante se escapa: nada de secuencias de control al terminal."""
    s = "".join(c if c.isprintable() else repr(c)[1:-1] for c in str(valor))
    return s if ancho is None else s[:ancho]


def pinta(d):
    sev = d.get("severidad", "baja")
    sev = sev if sev in C else "baja"
    u, p, ip = visible(d.get("usuario", "")), visible(d.get("contrasena", "")), visible(d.get("ip", "?"))
    tot[sev] += 1
    usuarios[u] = usuarios.get(u, 0) + 1
    contrasenas[p] = contrasenas.get(p, 0) + 1
    ips[ip] = ips.get(ip, 0) + 1
    print(f"{D}{visible(d.get('ts', ''))[:19]}{R}  {ip:>15}  {visible(d.get('puerto', '')):>5}  "
          f"{B}{u[:20]:<20}{R}  {p[:20]:<20}  {C[sev]}{sev.upper():<8}{R}", flush=True)


def resumen():
    print(f"\n{B}--- resumen ---{R}")
    print("  " + "  ".join(f"{C.get(k, '')}{k}: {v}{R}" for k, v in tot.items()))
    top = lambda d: ", ".join(f"{k} ({v})" for k, v in sorted(d.items(), key=lambda x: -x[1])[:5])
    print(f"  {D}IPs:{R} {top(ips) or '-'}")
    print(f"  {D}usuarios:{R} {top(usuarios) or '-'}")
    print(f"  {D}contraseñas:{R} {top(contrasenas) or '-'}")


if not os.path.exists(ruta):
    if not seguir:
        print(f"todavía no hay registros en {ruta}")
        sys.exit(0)
    print(f"esperando a que el honeypot cree {ruta}...", flush=True)
    while not os.path.exists(ruta):
        time.sleep(1)

print(f"{B}{'FECHA':19}  {'IP':>15}  {'PUERTO':>5}  {'USUARIO':<20}  {'CONTRASEÑA':<20}  SEVERIDAD{R}")
print(D + "-" * 90 + R)
try:
    with open(ruta, encoding="utf-8", errors="replace") as f:
        while True:
            linea = f.readline()
            if not linea:
                if not seguir:
                    break
                time.sleep(0.5)
                continue
            try:
                pinta(json.loads(linea))
            except (ValueError, AttributeError):
                pass
except KeyboardInterrupt:
    print()
resumen()
PY
