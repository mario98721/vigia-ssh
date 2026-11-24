#!/usr/bin/env bash
# ver_alertas.sh — alertas y bloqueos de vigia_ssh.py en formato de tabla.
# Uso: ver_alertas.sh [-f]
#   -f   sigue el log en vivo
# El log sigue siendo JSON (el contrato del ejercicio); esto solo lo presenta.
set -euo pipefail
LOG=${VIGIA_LOG:-/var/log/vigia/alertas.log}
if [[ -e $LOG && ! -r $LOG ]]; then echo "sin permisos sobre $LOG (usa sudo)"; exit 1; fi
python3 - "$LOG" "${1:-}" <<'PY'
import json
import os
import re
import sys
import time

ruta = sys.argv[1]
seguir = len(sys.argv) > 2 and sys.argv[2] == "-f"
C = {"media": "\033[33m", "alta": "\033[91m", "critica": "\033[1;91m"}
R, B, D, M, V = "\033[0m", "\033[1m", "\033[2m", "\033[95m", "\033[32m"
tot = {"media": 0, "alta": 0, "critica": 0}
ips, bloqueos = {}, 0
EVENTO = re.compile(r"^(bloqueada|desbloqueada) (\S+)(?: con (\S+))?")
# Otros avisos del log, puestos en columnas: (patrón, texto, color)
AVISOS = (
    (re.compile(r"^desbloqueo pedido para (\S+), que no estaba bloqueada"), "ya estaba desbloqueada", "\033[2m"),
    (re.compile(r"^(\S+) sube a (\w+) durante el enfriamiento"), "sube a {} (sin alerta nueva)", "\033[33m"),
    (re.compile(r"^FALLO de envío de \w+ (\S+):"), "envío fallido, en cola", "\033[91m"),
)


def visible(valor):
    """Los usuarios los elige el atacante: nada de secuencias de control al terminal."""
    return "".join(c if c.isprintable() else repr(c)[1:-1] for c in str(valor))


def fila(ts="", tipo="", host="", ip="", intentos="", ventana="", sev="", usuarios=""):
    """Una fila con las columnas del JSON de la alerta. sev ya viene con su color."""
    print(f"{D}{visible(ts):<20}{R}  {visible(tipo):<10}  {visible(host)[:12]:<12}  {visible(ip):>15}  "
          f"{visible(intentos):>8}  {visible(ventana):>11}  {sev}  {usuarios}", flush=True)


def usuarios_cortos(lista, ancho=30):
    """Tantos usuarios como quepan en la columna y, si sobran, cuántos faltan."""
    lista = [visible(u) for u in lista]
    if not lista:
        return "-"
    texto, n = lista[0][:ancho - 8] + ("…" if len(lista[0]) > ancho - 8 else ""), 1
    while n < len(lista) and len(texto) + 2 + len(lista[n]) + 6 <= ancho:
        texto, n = texto + ", " + lista[n], n + 1
    return texto + (f" {D}+{len(lista) - n}{R}" if n < len(lista) else "")


def pinta(linea):
    global bloqueos
    ts, _, msg = linea.rstrip("\n").partition(" ")
    if msg.startswith("{"):
        try:
            a = json.loads(msg)
        except ValueError:
            return
        if not isinstance(a, dict) or a.get("tipo") != "alerta_ssh":
            return
        sev = a.get("severidad") if a.get("severidad") in C else "media"
        ip = visible(a.get("ip", "?"))
        tot[sev] += 1
        ips[ip] = ips.get(ip, 0) + 1
        fila(a.get("ts", ts), a.get("tipo", ""), a.get("host", ""), ip, a.get("intentos", ""),
             a.get("ventana_min", ""), f"{C[sev]}{sev.upper():<9}{R}",
             usuarios_cortos(a.get("usuarios") or []))
        return
    m = EVENTO.match(msg)
    if m:
        accion, ip, metodo = m.groups()
        if accion == "bloqueada":
            bloqueos += 1
            texto = f"{M}BLOQUEADA{R}" + (f" {D}({metodo}){R}" if metodo else "")
        else:
            texto = f"{V}desbloqueada{R}"
        fila(ts, ip=ip, sev=texto)
        return
    for patron, texto, color in AVISOS:
        m = patron.match(msg)
        if m:
            extra = (visible(x).upper() for x in m.groups()[1:])
            fila(ts, ip=m.group(1), sev=f"{color}{texto.format(*extra)}{R}")
            return
    if msg:
        print(f"{D}{visible(ts):<20}  {visible(msg)}{R}", flush=True)


def resumen():
    print(f"\n{B}--- resumen ---{R}")
    print("  " + "  ".join(f"{C[k]}{k}: {v}{R}" for k, v in tot.items()) + f"  {M}bloqueos: {bloqueos}{R}")
    top = ", ".join(f"{k} ({v})" for k, v in sorted(ips.items(), key=lambda x: -x[1])[:5])
    print(f"  {D}IPs:{R} {top or '-'}")


if not os.path.exists(ruta):
    if not seguir:
        print(f"todavía no hay alertas en {ruta}")
        sys.exit(0)
    print(f"esperando a que vigia_ssh.py cree {ruta}...", flush=True)
    while not os.path.exists(ruta):
        time.sleep(1)

print(f"{B}{'TS':<20}  {'TIPO':<10}  {'HOST':<12}  {'IP':>15}  {'INTENTOS':>8}  {'VENTANA_MIN':>11}  "
      f"{'SEVERIDAD':<9}  USUARIOS{R}")
print(D + "-" * 130 + R)
try:
    f = open(ruta, encoding="utf-8", errors="replace")
    while True:
        linea = f.readline()
        if linea:
            pinta(linea)
            continue
        if not seguir:
            break
        time.sleep(0.5)
        try:  # al pasar de 1 MB el log se rota: se vuelve a abrir el nuevo
            if os.stat(ruta).st_ino != os.fstat(f.fileno()).st_ino:
                f.close()
                f = open(ruta, encoding="utf-8", errors="replace")
        except FileNotFoundError:
            pass
except KeyboardInterrupt:
    print()
resumen()
PY
