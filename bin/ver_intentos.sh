#!/usr/bin/env bash
# ver_intentos.sh — intentos SSH del journal en formato de tabla.
# Uso: ver_intentos.sh [-f] [minutos]
#   -f        sigue el journal en vivo
#   minutos   ventana hacia atrás (def. 30)
# Lee las unidades ssh y sshd (Debian/Ubuntu y RHEL/Fedora/Arch respectivamente).
set -euo pipefail
seguir=0
if [[ ${1:-} == "-f" ]]; then seguir=1; shift; fi
VENTANA=${1:-30}
[[ $VENTANA =~ ^[0-9]+$ ]] || { echo "uso: $0 [-f] [minutos]"; exit 1; }
python3 - "$VENTANA" "$seguir" <<'PY'
import json
import os
import re
import subprocess
import sys
from datetime import datetime

ventana = int(sys.argv[1])
seguir = sys.argv[2] == "1"

# Mismo criterio que vigia_ssh.py: la IP sale del final de la línea, que el atacante
# no controla (el usuario puede llevar espacios y un "from <otra IP>" inventado).
FIN = r" from (?P<ip>[0-9A-Fa-f.:]+) port (?P<puerto>\d+)(?: ssh2)?$"
PATRONES = (
    ("fallo", re.compile(r"^Failed password for (?:invalid user )?(?P<usuario>.*)" + FIN)),
    ("acceso", re.compile(r"^Accepted (?:password|keyboard-interactive/pam) for (?P<usuario>.*)" + FIN)),
    ("fallo", re.compile(r"^error: PAM: Authentication failure for (?:illegal user )?"
                         r"(?P<usuario>.*) from (?P<ip>[0-9A-Fa-f.:]+)$")),
)

UMBRAL = 5   # más de UMBRAL intentos de una IP -> alta

C = {"baja": "\033[36m", "media": "\033[33m", "alta": "\033[91m",
     "critica": "\033[1;91m"}
R, B, D = "\033[0m", "\033[1m", "\033[2m"
HOST = os.uname().nodename
tot = {"baja": 0, "media": 0, "alta": 0, "critica": 0}
usuarios, ips = {}, {}


def severidad(tipo, intentos):
    # critica: acceso correcto. alta: la IP pasa de UMBRAL intentos. baja: por debajo.
    if tipo == "acceso":
        return "critica"
    return "alta" if intentos > UMBRAL else "baja"


def pinta(usuario, ip, puerto, tipo, ts, etiqueta):
    usuarios[usuario] = usuarios.get(usuario, 0) + 1
    ips[ip] = ips.get(ip, 0) + 1
    sev = severidad(tipo, ips[ip])
    tot[sev] = tot.get(sev, 0) + 1
    # Mismas columnas que la alerta JSON. intentos = total acumulado de esa IP
    # (1, 2, 3...); severidad sube a alta al pasar de UMBRAL.
    print(f"{D}{ts:<20}{R}  {'intento_ssh':<11}  {HOST[:12]:<12}  {ip:>15}  "
          f"{ips[ip]:>8}  {'-':>11}  {C[sev]}{sev.upper():<9}{R}  {B}{usuario[:24]}{R}", flush=True)


def procesa(linea):
    try:
        obj = json.loads(linea)
    except ValueError:
        return
    msg = obj.get("MESSAGE") if isinstance(obj, dict) else None
    if not isinstance(msg, str):
        return
    for tipo, patron in PATRONES:
        m = patron.match(msg)
        if m:
            break
    else:
        return
    try:
        ts = datetime.fromtimestamp(int(obj["__REALTIME_TIMESTAMP"]) / 1_000_000)
        ts = f"{ts:%Y-%m-%dT%H:%M:%S}"
    except (KeyError, ValueError):
        ts = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    usuario = "".join(c if c.isprintable() else "?" for c in m.group("usuario"))
    puerto = m.groupdict().get("puerto") or "-"
    etiqueta = "ACCESO" if tipo == "acceso" else "fallo"
    pinta(usuario, m.group("ip"), puerto, tipo, ts, etiqueta)


print(f"{B}{'TS':<20}  {'TIPO':<11}  {'HOST':<12}  {'IP':>15}  {'INTENTOS':>8}  "
      f"{'VENTANA_MIN':>11}  {'SEVERIDAD':<9}  USUARIOS{R}")
print(D + "-" * 120 + R)

UNIDADES = ["-u", "ssh", "-u", "sshd"]
try:
    if seguir:
        # -n 0: no arrastra el histórico del journal, solo sigue lo nuevo desde ahora.
        p = subprocess.Popen(["journalctl", *UNIDADES, "-f", "-n", "0", "-o", "json", "-q"],
                             stdout=subprocess.PIPE, text=True, errors="replace", bufsize=1)
        # readline en vez de "for linea in p.stdout": este último hace read-ahead y
        # retiene las líneas en un buffer, así que no saldrían en tiempo real.
        for linea in iter(p.stdout.readline, ""):
            procesa(linea)
    else:
        r = subprocess.run(["journalctl", *UNIDADES, "-o", "json", "-q",
                            "--since", f"-{ventana} min"], capture_output=True, text=True,
                           errors="replace")
        for linea in r.stdout.splitlines():
            procesa(linea)
except KeyboardInterrupt:
    print()

resumen_tot = "  ".join(f"{C.get(k, '')}{k}: {v}{R}" for k, v in tot.items())
top = lambda d: ", ".join(f"{k} ({v})" for k, v in sorted(d.items(), key=lambda x: -x[1])[:5])
print(f"\n{B}--- resumen ---{R}\n  {resumen_tot}")
print(f"  {D}IPs:{R} {top(ips) or '-'}")
print(f"  {D}usuarios:{R} {top(usuarios) or '-'}")
PY
