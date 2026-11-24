#!/usr/bin/env python3
"""vigia_ssh.py — Detector de fuerza bruta SSH con alertas y bloqueo opcional.

Lee el journal de sshd en JSON (journalctl -o json) o un fichero JSON Lines,
agrupa los fallos de autenticación por IP dentro de una ventana, calcula la
severidad y envía un JSON al webhook. No repite alertas de la misma IP durante
el enfriamiento y, si se pide, bloquea la IP con nftables (o iptables).

Ampliaciones: modo continuo, severidad crítica si hay acceso tras los fallos,
lista blanca con redes CIDR e IPs locales automáticas, bloqueo IPv4/IPv6 con
expiración, cola de reintentos del webhook, resumen periódico y autotest.
"""
import argparse
import atexit
import fcntl
import ipaddress
import json
import os
import queue
import random
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from collections import deque
from pathlib import Path

VERSION = "1.1.0"

CONF = Path(os.environ.get("VIGIA_CONF", "/etc/vigia/vigia.conf"))
LISTA_BLANCA = Path(os.environ.get("VIGIA_LISTA_BLANCA", "/etc/vigia/lista_blanca.json"))
ESTADO = Path(os.environ.get("VIGIA_ESTADO", "/var/lib/vigia/estado.json"))
LOG = Path(os.environ.get("VIGIA_LOG", "/var/log/vigia/alertas.log"))
LOCK = Path(os.environ.get("VIGIA_LOCK", "/var/lib/vigia/vigia.lock"))
MUESTRA = Path(os.environ.get("VIGIA_MUESTRA", "/var/lib/vigia/muestra_ssh.jsonl"))

DEFECTOS = {
    "UMBRAL": 5, "VENTANA_MIN": 5, "ENFRIAMIENTO": 600, "RESUMEN_MIN": 5,
    "DESBLOQUEO_MIN": 0, "BLOQUEO_MIN_SEV": "alta", "CANAL": "", "THROTTLE": 10,
    "UNIDADES": "ssh sshd",
}
PESO = {"media": 1, "alta": 2, "critica": 3}
MAX_LARGO_USUARIO = 32   # caracteres por usuario en los mensajes de Discord
MAX_PENDIENTES = 50      # alertas sin entregar que se guardan para reintentar
TABLA = "vigia"          # tabla inet de nftables

# sshd escribe el usuario tal como lo manda el cliente, con espacios incluidos:
# "Failed password for invalid user x from 10.0.2.50 from 203.0.113.9 port 4242 ssh2".
# Por eso la IP se toma siempre del FINAL de la línea, la parte que el atacante
# no controla, y el usuario es "todo lo de en medio" (.* codicioso).
_FIN = r" from (?P<ip>[0-9A-Fa-f.:]+) port \d+(?: ssh2)?$"
PATRONES = (
    ("fallo", re.compile(r"^Failed password for (?:invalid user )?(?P<usuario>.*)" + _FIN)),
    ("acceso", re.compile(r"^Accepted (?:password|keyboard-interactive/pam) for (?P<usuario>.*)" + _FIN)),
    # keyboard-interactive con PAM: "Failed keyboard-interactive/pam" solo sale a nivel
    # INFO para usuarios inexistentes; esta otra línea sale siempre, una por intento.
    ("fallo", re.compile(r"^error: PAM: Authentication failure for (?:illegal user )?"
                         r"(?P<usuario>.*) from (?P<ip>[0-9A-Fa-f.:]+)$")),
)

UMBRAL = VENTANA_MIN = ENFRIAMIENTO = RESUMEN_MIN = DESBLOQUEO_MIN = 0
BLOQUEO_MIN_SEV = "alta"
CANAL = ""
THROTTLE = 10
UNIDADES = ["ssh", "sshd"]
BLOQUEAR = SI = DRY = False
_AVISADAS = set()


def iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def log(msg: str) -> None:
    try:
        if LOG.is_file() and LOG.stat().st_size > 1_048_576:
            LOG.replace(LOG.with_name(LOG.name + ".1"))
        with LOG.open("a", encoding="utf-8") as f:
            f.write(f"{iso()} {msg}\n")
    except OSError:
        pass


def carga_conf() -> dict:
    cfg = dict(DEFECTOS)
    if CONF.is_file():
        for linea in CONF.read_text(encoding="utf-8", errors="replace").splitlines():
            linea = linea.split(" #", 1)[0].strip()
            if not linea or linea.startswith("#") or "=" not in linea:
                continue
            k, v = linea.split("=", 1)
            cfg[k.strip()] = v.strip().strip('"').strip("'")
    return cfg


def carga_estado() -> dict:
    try:
        st = json.loads(ESTADO.read_text(encoding="utf-8"))
        if not isinstance(st, dict) or not isinstance(st.get("ips", {}), dict):
            raise ValueError("estado con forma inesperada")
        st.setdefault("ips", {})
        return st
    except Exception:
        return {"ips": {}}


def guarda_estado(st: dict) -> None:
    st["actualizado"] = iso()
    tmp = ESTADO.with_suffix(".tmp")
    tmp.write_text(json.dumps(st, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, ESTADO)


def carga_lista_blanca() -> list:
    try:
        datos = json.loads(LISTA_BLANCA.read_text(encoding="utf-8"))
        return [str(x) for x in datos] if isinstance(datos, list) else []
    except Exception:
        return []


def ips_locales() -> set:
    salida = set()
    try:
        r = subprocess.run(["ip", "-o", "addr", "show"], capture_output=True, text=True, timeout=5)
        for linea in r.stdout.splitlines():
            partes = linea.split()
            if len(partes) > 3 and partes[2] in ("inet", "inet6"):
                salida.add(partes[3].split("/")[0])
    except Exception:
        pass
    return salida


def a_redes(entradas) -> list:
    """Convierte IPs o redes CIDR en ip_network; avisa una vez de las que no valen."""
    redes = []
    for x in entradas:
        try:
            redes.append(ipaddress.ip_network(str(x).strip(), strict=False))
        except ValueError:
            if x not in _AVISADAS:
                _AVISADAS.add(x)
                log(f"lista blanca: entrada no válida ignorada: {x!r}")
    return redes


def normaliza_ip(ip: str):
    """Devuelve la IP en forma canónica (IPv4 si es IPv4-mapeada) o None si no es una IP."""
    try:
        d = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if getattr(d, "ipv4_mapped", None):
        d = d.ipv4_mapped
    return str(d)


def en_lista_blanca(ip: str, redes: list) -> bool:
    d = ipaddress.ip_address(ip)
    if d.is_loopback:
        return True
    return any(d.version == r.version and d in r for r in redes)


def limpia(texto: str, maximo: int = MAX_LARGO_USUARIO) -> str:
    """Recorta y cambia por '?' lo que no se ve o rompe formatos (control y `)."""
    texto = "".join(c if c.isprintable() and c != "`" else "?" for c in texto)
    return texto if len(texto) <= maximo else texto[: maximo - 1] + "…"


def parsea(linea: str, corte: int):
    try:
        obj = json.loads(linea)
    except Exception:
        return None
    if not isinstance(obj, dict):
        return None
    msg = obj.get("MESSAGE")
    if not isinstance(msg, str):
        return None
    try:
        ts = int(obj.get("__REALTIME_TIMESTAMP", 0))
    except (TypeError, ValueError):
        ts = 0
    if ts < corte:
        return None
    for tipo, patron in PATRONES:
        m = patron.match(msg)
        if m:
            ip = normaliza_ip(m.group("ip"))
            if ip is None:
                return None
            return {"tipo": tipo, "usuario": m.group("usuario"), "ip": ip, "ts": ts}
    return None


def _cmd_journal(*extra) -> list:
    cmd = ["journalctl", "-o", "json", "-q", *extra]
    for unidad in UNIDADES:
        cmd += ["-u", unidad]
    return cmd


def lineas_journal(minutos: int = 0) -> list:
    r = subprocess.run(_cmd_journal("--since", f"-{minutos or VENTANA_MIN} min"),
                       capture_output=True, text=True, errors="replace")
    if r.returncode != 0:
        detalle = (r.stderr or "").strip().splitlines()[:1]
        log(f"ERROR journalctl terminó con {r.returncode}: {detalle}")
        print(f"journalctl falló ({r.returncode}); ¿lo ejecutas con sudo?", file=sys.stderr)
    return r.stdout.splitlines()


def es_discord(url: str) -> bool:
    host = (urllib.parse.urlsplit(url).hostname or "").lower()
    return host in ("discord.com", "discordapp.com") or host.endswith((".discord.com", ".discordapp.com"))


COLOR_DISCORD = {"media": 0xF1C40F, "alta": 0xE67E22, "critica": 0xE74C3C}
LIMITE_CAMPO = 1024      # caracteres por campo de un embed de Discord


def _lista(nombres: list, limite: int = LIMITE_CAMPO, limpiar: bool = True) -> str:
    """Nombres en un bloque de código, recortados para caber en un campo del embed.
    Si no caben todos, se dice cuántos faltan; el JSON del contrato los lleva todos."""
    nombres = [limpia(str(n)) if limpiar else str(n) for n in nombres]

    def con(n):
        resto = [f"… y {len(nombres) - n} más"] if n < len(nombres) else []
        return "```\n" + ", ".join(nombres[:n] + resto) + "\n```"

    cabe, no_cabe = 0, len(nombres)
    while cabe < no_cabe:  # búsqueda binaria del mayor número de nombres que cabe
        medio = (cabe + no_cabe + 1) // 2
        if len(con(medio)) <= limite:
            cabe = medio
        else:
            no_cabe = medio - 1
    return con(cabe) if nombres else "-"


def formato_discord(payload: dict) -> dict:
    """Tarjeta (embed) para Discord con color según la severidad. Solo cambia la
    presentación: a cualquier otro webhook le llega el JSON del contrato tal cual."""
    host = limpia(str(payload.get("host", "")), 64)
    if payload.get("tipo") == "resumen_ssh":
        ips = [f"{x.get('ip')} ({x.get('intentos')})" for x in payload.get("top_ips", [])]
        usuarios = [f"{limpia(str(x.get('usuario', '')))} ({x.get('intentos')})"
                    for x in payload.get("top_usuarios", [])]
        embed = {
            "title": f"Resumen SSH · últimos {payload.get('periodo_min')} min",
            "color": 0x3498DB,
            "fields": [
                {"name": "Fallos", "value": str(payload.get("fallos", 0)), "inline": True},
                {"name": "Host", "value": host or "-", "inline": True},
                {"name": "Top IPs", "value": _lista(ips, limpiar=False)},
                {"name": "Top usuarios", "value": _lista(usuarios, limpiar=False)},
            ],
        }
    else:
        sev = str(payload.get("severidad", ""))
        embed = {
            "title": f"Fuerza bruta SSH · {sev.upper()}",
            "color": COLOR_DISCORD.get(sev, 0x95A5A6),
            "fields": [
                {"name": "IP", "value": str(payload.get("ip", "")), "inline": True},
                {"name": "Intentos", "value": f"{payload.get('intentos')} en {payload.get('ventana_min')} min",
                 "inline": True},
                {"name": "Host", "value": host or "-", "inline": True},
                {"name": f"Usuarios ({len(payload.get('usuarios', []))})",
                 "value": _lista(payload.get("usuarios", []))},
            ],
        }
        if sev == "critica":
            embed["description"] = "Acceso correcto después de los fallos: revisa esa sesión."
    if payload.get("ts"):
        embed["timestamp"] = payload["ts"]
    embed["footer"] = {"text": "vigia-ssh"}
    # allowed_mentions vacío: ni un @everyone colado hace mención.
    return {"embeds": [embed], "allowed_mentions": {"parse": []}}


def envia(payload: dict, dry: bool) -> bool:
    texto = json.dumps(payload, ensure_ascii=False)
    if dry or not CANAL:
        print(texto, flush=True)
        return True
    cuerpo = formato_discord(payload) if es_discord(CANAL) else payload
    req = urllib.request.Request(
        CANAL, data=json.dumps(cuerpo, ensure_ascii=False).encode("utf-8"), method="POST",
        headers={"Content-Type": "application/json", "User-Agent": f"vigia-ssh/{VERSION}"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310 (esquema validado en main)
            return 200 <= resp.status < 300
    except Exception as exc:
        log(f"FALLO de envío de {payload.get('tipo')} {payload.get('ip', '')}: {type(exc).__name__}: {exc}")
        return False


def encola(payload: dict) -> None:
    st = carga_estado()
    pendientes = st.setdefault("pendientes", [])
    pendientes.append(payload)
    del pendientes[:-MAX_PENDIENTES]
    guarda_estado(st)


def reintenta_pendientes(dry: bool = False) -> None:
    if dry or not CANAL:
        return
    st = carga_estado()
    pendientes = st.get("pendientes") or []
    if not pendientes:
        return
    for i, p in enumerate(pendientes):
        if not envia(p, dry=False):
            st["pendientes"] = pendientes[i:]  # el canal sigue caído: lo demás, luego
            break
    else:
        st["pendientes"] = []
    guarda_estado(st)


def _nft(*args, entrada=None):
    if shutil.which("nft") is None:
        return subprocess.CompletedProcess(["nft", *args], 127, "", "nft no está instalado")
    return subprocess.run(["nft", *args], input=entrada, capture_output=True, text=True)


def asegura_tabla() -> bool:
    if shutil.which("nft") is None:
        return False
    if _nft("list", "table", "inet", TABLA).returncode != 0:
        r = _nft("-f", "-", entrada=(
            f"add table inet {TABLA}\n"
            f"add set inet {TABLA} bloqueadas {{ type ipv4_addr ; flags timeout ; }}\n"
            f"add set inet {TABLA} bloqueadas6 {{ type ipv6_addr ; flags timeout ; }}\n"
            f"add chain inet {TABLA} entrada {{ type filter hook input priority 0 ; policy accept ; }}\n"
            f"add rule inet {TABLA} entrada ip saddr @bloqueadas drop\n"
            f"add rule inet {TABLA} entrada ip6 saddr @bloqueadas6 drop\n"))
    elif _nft("list", "set", "inet", TABLA, "bloqueadas6").returncode != 0:
        # tabla creada por la versión 1.0, que solo tenía el conjunto IPv4
        r = _nft("-f", "-", entrada=(
            f"add set inet {TABLA} bloqueadas6 {{ type ipv6_addr ; flags timeout ; }}\n"
            f"add rule inet {TABLA} entrada ip6 saddr @bloqueadas6 drop\n"))
    else:
        return True
    if r.returncode != 0:
        log(f"ERROR nft al crear la tabla {TABLA}: {r.stderr.strip()}")
        return False
    return True


def bloquea_ip(ip: str):
    """Bloquea la IP. Devuelve el método usado ("nft", "iptables"...) o None si falla."""
    version = ipaddress.ip_address(ip).version
    tope = f" timeout {DESBLOQUEO_MIN}m" if DESBLOQUEO_MIN > 0 else ""
    if asegura_tabla():
        conjunto = "bloqueadas" if version == 4 else "bloqueadas6"
        r = _nft("add", "element", "inet", TABLA, conjunto, f"{{ {ip}{tope} }}")
        if r.returncode == 0:
            return "nft"
        log(f"ERROR nft al bloquear {ip}: {r.stderr.strip()}")
        return None
    binario = "iptables" if version == 4 else "ip6tables"
    if shutil.which(binario) is None:
        log(f"ERROR no hay nft ni {binario}: {ip} no se puede bloquear")
        return None
    regla = ["INPUT", "-s", ip, "-j", "DROP"]
    if subprocess.run([binario, "-C", *regla], capture_output=True).returncode == 0:
        return binario  # ya estaba; no se duplica la regla
    r = subprocess.run([binario, "-I", *regla], capture_output=True, text=True)
    if r.returncode == 0:
        return binario
    log(f"ERROR {binario} al bloquear {ip}: {r.stderr.strip()}")
    return None


def desbloquea_ip(ip: str) -> bool:
    """Quita la IP de nftables e iptables. Devuelve True si había algo que quitar."""
    d = ipaddress.ip_address(ip)
    quitada = False
    if shutil.which("nft"):
        conjunto = "bloqueadas" if d.version == 4 else "bloqueadas6"
        quitada |= _nft("delete", "element", "inet", TABLA, conjunto, f"{{ {d} }}").returncode == 0
    binario = "iptables" if d.version == 4 else "ip6tables"
    if shutil.which(binario):
        for _ in range(100):  # también las reglas duplicadas por versiones anteriores
            if subprocess.run([binario, "-D", "INPUT", "-s", str(d), "-j", "DROP"],
                              capture_output=True).returncode != 0:
                break
            quitada = True
    st = carga_estado()
    if str(d) in st["ips"]:
        st["ips"][str(d)]["bloqueada"] = False
        st["ips"][str(d)].pop("bloqueo", None)
        guarda_estado(st)
    log(f"desbloqueada {d}" if quitada else f"desbloqueo pedido para {d}, que no estaba bloqueada")
    return quitada


def bloqueadas_actuales() -> list:
    if shutil.which("nft") is None:
        return []
    salida = []
    for conjunto in ("bloqueadas", "bloqueadas6"):
        r = _nft("-j", "list", "set", "inet", TABLA, conjunto)
        if r.returncode != 0:
            continue
        try:
            datos = json.loads(r.stdout or "{}")
        except ValueError:
            continue
        for bloque in datos.get("nftables", []):
            for elem in (bloque.get("set") or {}).get("elem", []) or []:
                valor = elem.get("elem", {}).get("val") if isinstance(elem, dict) else elem
                if valor:
                    salida.append(str(valor))
    return salida


def confirma(ip: str, sev: str) -> bool:
    if SI:
        return True
    try:
        with open("/dev/tty", "r+") as tty:
            tty.write(f"¿Bloquear {ip} (severidad {sev})? [s/N] ")
            tty.flush()
            return tty.readline().strip().lower().startswith("s")
    except OSError:
        # Sin terminal (cron, servicio, tubería) no se puede preguntar: no se bloquea.
        log(f"sin terminal para confirmar el bloqueo de {ip}; no se bloquea (usa -s)")
        print(f"  sin terminal para confirmar; {ip} NO se bloquea (usa -s)", file=sys.stderr)
        return False


def bloquea(ip: str, sev: str, dry: bool) -> bool:
    if PESO.get(sev, 0) < PESO[BLOQUEO_MIN_SEV] or not BLOQUEAR:
        return False
    if dry:
        print(f"  (dry-run) bloquearía {ip}", file=sys.stderr)
        return False
    try:
        if ipaddress.ip_address(ip).is_loopback:
            return False
    except ValueError:
        log(f"IP inválida, no se bloquea: {ip}")
        return False
    if not confirma(ip, sev):
        return False
    metodo = bloquea_ip(ip)
    if not metodo:
        print(f"  NO se pudo bloquear {ip}; detalle en {LOG}", file=sys.stderr)
        return False
    hasta = int(time.time()) + DESBLOQUEO_MIN * 60 if DESBLOQUEO_MIN > 0 else 0
    st = carga_estado()
    st["ips"].setdefault(ip, {}).update({"bloqueada": True, "bloqueo": {"metodo": metodo, "hasta": hasta}})
    guarda_estado(st)
    log(f"bloqueada {ip} con {metodo} (severidad {sev})")
    print(f"  bloqueada {ip}", file=sys.stderr)
    return True


def analiza(lineas, dry: bool = False):
    ahora = int(time.time())
    corte = (ahora - VENTANA_MIN * 60) * 1_000_000

    grupos = {}
    for linea in lineas:  # el journal llega en orden cronológico
        ev = parsea(linea, corte)
        if not ev:
            continue
        g = grupos.setdefault(ev["ip"], {"intentos": 0, "usuarios": set(), "aceptado": False})
        if ev["tipo"] == "fallo":
            g["intentos"] += 1
            g["usuarios"].add(ev["usuario"])
        elif g["intentos"] > 0:
            g["aceptado"] = True  # acceso DESPUÉS de fallos: probablemente acertó

    st = carga_estado()
    blancas = a_redes(carga_lista_blanca()) + a_redes(ips_locales())

    alertas, omitidas = [], 0
    for ip, g in grupos.items():
        if g["intentos"] < UMBRAL:
            continue
        if en_lista_blanca(ip, blancas):
            omitidas += 1
            continue
        sev = "critica" if g["aceptado"] else ("alta" if g["intentos"] >= UMBRAL * 2 else "media")
        previo = st["ips"].get(ip, {})
        ultima = previo.get("ultima", 0)
        # En enfriamiento: una sola alerta por ráfaga. Si la ráfaga sigue y pasa de media a
        # alta, se bloquea sin volver a avisar. Solo un acceso conseguido (critica) avisa de nuevo.
        sev_previa = previo.get("severidad")
        if ahora - ultima < ENFRIAMIENTO and not (sev == "critica" and sev_previa != "critica"):
            omitidas += 1
            if PESO[sev] > PESO.get(sev_previa, 0):
                st["ips"][ip] = {**previo, "severidad": sev, "intentos": g["intentos"]}
                guarda_estado(st)
                log(f"{ip} sube a {sev} durante el enfriamiento (sin alerta nueva)")
                bloquea(ip, sev, dry)
                st = carga_estado()
            else:
                print(f"Omite alerta duplicada para {ip} (quedan {ENFRIAMIENTO - (ahora - ultima)}s)",
                      file=sys.stderr)
            continue
        # Contrato del ejercicio, campo a campo: lista completa de usuarios, sin duplicados.
        alertas.append({
            "tipo": "alerta_ssh", "host": os.uname().nodename, "ts": iso(), "ip": ip,
            "intentos": g["intentos"], "ventana_min": VENTANA_MIN,
            "usuarios": sorted(g["usuarios"]), "severidad": sev,
        })

    alertas.sort(key=lambda a: -a["intentos"])
    for a in alertas:
        st = carga_estado()
        previo = st["ips"].get(a["ip"], {})
        st["ips"][a["ip"]] = {**previo, "ultima": ahora, "intentos": a["intentos"],
                              "severidad": a["severidad"]}
        guarda_estado(st)
        # El bloqueo no depende del webhook: si el canal falla, la IP se bloquea igual.
        bloquea(a["ip"], a["severidad"], dry)
        log(json.dumps(a, ensure_ascii=False))
        if not envia(a, dry):
            print(f"  envío fallido para {a['ip']}; queda en cola para reintentarlo", file=sys.stderr)
            encola(a)
    return len(alertas), omitidas


def resumen(lineas=None) -> None:
    periodo = max(RESUMEN_MIN, VENTANA_MIN)
    corte = (int(time.time()) - periodo * 60) * 1_000_000
    if lineas is None:
        lineas = lineas_journal(periodo)
    ips, usuarios, total = {}, {}, 0
    for linea in lineas:
        ev = parsea(linea, corte)
        if ev and ev["tipo"] == "fallo":
            total += 1
            ips[ev["ip"]] = ips.get(ev["ip"], 0) + 1
            usuarios[ev["usuario"]] = usuarios.get(ev["usuario"], 0) + 1
    if not total:
        return

    def top(d, k):
        return [{k: v, "intentos": n} for v, n in sorted(d.items(), key=lambda x: (-x[1], x[0]))[:5]]

    envia({"tipo": "resumen_ssh", "host": os.uname().nodename, "ts": iso(), "periodo_min": periodo,
           "fallos": total, "top_ips": top(ips, "ip"), "top_usuarios": top(usuarios, "usuario")}, DRY)


def mantenimiento(dry: bool = False) -> None:
    """Caduca bloqueos de iptables, poda el estado y reintenta alertas pendientes."""
    ahora = int(time.time())
    for ip, e in list(carga_estado()["ips"].items()):
        b = e.get("bloqueo") or {}
        if b.get("metodo") in ("iptables", "ip6tables") and b.get("hasta") and ahora >= b["hasta"]:
            desbloquea_ip(ip)  # nftables caduca solo gracias al timeout del elemento
    st = carga_estado()
    limite = ahora - 7 * 86400
    conservar = {ip: e for ip, e in st["ips"].items() if e.get("ultima", 0) >= limite or e.get("bloqueada")}
    if len(conservar) != len(st["ips"]):
        st["ips"] = conservar
        guarda_estado(st)
    reintenta_pendientes(dry)


def _lineas_prueba(base: int) -> list:
    lineas = [json.dumps({"__REALTIME_TIMESTAMP": f"{(base - 290) * 1_000_000}",
                          "MESSAGE": "Accepted password for kali from 10.0.2.20 port 40100 ssh2"})]
    for i in range(12):
        lineas.append(json.dumps({
            "__REALTIME_TIMESTAMP": f"{(base - 200 + i * 5) * 1_000_000}",
            "MESSAGE": f"Failed password for invalid user root from 10.0.2.24 port {30000 + i} ssh2"}))
    for i in range(11):
        lineas.append(json.dumps({
            "__REALTIME_TIMESTAMP": f"{(base - 100 + i * 3) * 1_000_000}",
            "MESSAGE": f"Failed password for invalid user admin from 10.0.2.23 port {40000 + i} ssh2"}))
    lineas.append(json.dumps({"__REALTIME_TIMESTAMP": f"{(base - 5) * 1_000_000}",
                              "MESSAGE": "Accepted password for kali from 10.0.2.23 port 41999 ssh2"}))
    lineas.append(json.dumps({"__REALTIME_TIMESTAMP": f"{(base - 3) * 1_000_000}",
                              "MESSAGE": "Failed password for root from 10.0.2.20 port 5555 ssh2"}))
    return lineas


def autotest() -> int:
    global ESTADO, LOG, DRY, BLOQUEAR, ips_locales, carga_lista_blanca
    lineas = _lineas_prueba(int(time.time()))
    guardado = (ESTADO, LOG, DRY, BLOQUEAR, ips_locales, carga_lista_blanca)
    esperado = {"10.0.2.24": "alta", "10.0.2.23": "critica"}
    print("--- esperado: 10.0.2.24 (alta), 10.0.2.23 (critica), 10.0.2.20 silenciada ---")
    # Todo va a un directorio temporal: el estado y el log reales no se tocan.
    with tempfile.TemporaryDirectory(prefix="vigia-autotest-") as tmp:
        ESTADO, LOG = Path(tmp) / "estado.json", Path(tmp) / "alertas.log"
        ESTADO.write_text('{"ips":{}}', encoding="utf-8")
        DRY, BLOQUEAR = True, False
        ips_locales = lambda: set()  # noqa: E731
        carga_lista_blanca = lambda: ["10.0.2.20"]  # noqa: E731
        try:
            n, _ = analiza(lineas, dry=True)
            datos = carga_estado()["ips"]
            obtenido = {ip: e.get("severidad") for ip, e in datos.items()}
            ok = n == 2 and obtenido == esperado
            if not ok:
                print(f"obtenido: {obtenido}")
        except Exception as exc:
            print(f"excepción: {exc}")
            ok = False
        finally:
            ESTADO, LOG, DRY, BLOQUEAR, ips_locales, carga_lista_blanca = guardado
    print("AUTOTEST OK" if ok else "AUTOTEST FALLIDO")
    return 0 if ok else 1


def demo() -> int:
    global ESTADO, LOG, TABLA, BLOQUEAR, SI, ips_locales, carga_lista_blanca
    guardado = (ESTADO, LOG, TABLA, BLOQUEAR, SI, ips_locales, carga_lista_blanca)
    tmp = Path(tempfile.mkdtemp(prefix="vigia-demo-"))
    # Estado, log y tabla propios: la demo no pisa los bloqueos ni el estado reales.
    ESTADO, LOG, TABLA = tmp / "estado.json", tmp / "alertas.log", "vigia_demo"
    ips_locales = lambda: set()  # noqa: E731
    carga_lista_blanca = lambda: ["10.0.2.20"]  # noqa: E731
    BLOQUEAR, SI = True, True
    try:
        print("=== 0. Comprobando el canal ===")
        if not CANAL:
            print("sin canal: las alertas se imprimen aquí")
        elif envia({"tipo": "demo_inicio", "mensaje": "arranque"}, dry=False):
            print("canal accesible")
        else:
            print("el canal no responde; las alertas quedarán en cola")

        print("\n=== 1. Generando muestra (14 fallos .24, 11 fallos + acceso .23, 1 fallo .20) ===")
        base = int(time.time())
        lineas = [json.dumps({"__REALTIME_TIMESTAMP": f"{(base - 290) * 1_000_000}",
                              "MESSAGE": "Accepted password for kali from 10.0.2.20 port 40100 ssh2"})]
        for i in range(14):
            usuario = random.choice(["root", "admin", "oracle", "test"])  # noqa: S311
            lineas.append(json.dumps({
                "__REALTIME_TIMESTAMP": f"{(base - 240 + i * 6) * 1_000_000}",
                "MESSAGE": f"Failed password for invalid user {usuario} from 10.0.2.24 port {30000 + i} ssh2"}))
        for i in range(11):
            usuario = random.choice(["admin", "test"])  # noqa: S311
            lineas.append(json.dumps({
                "__REALTIME_TIMESTAMP": f"{(base - 120 + i * 4) * 1_000_000}",
                "MESSAGE": f"Failed password for invalid user {usuario} from 10.0.2.23 port {40000 + i} ssh2"}))
        lineas.append(json.dumps({"__REALTIME_TIMESTAMP": f"{(base - 5) * 1_000_000}",
                                  "MESSAGE": "Accepted password for kali from 10.0.2.23 port 41999 ssh2"}))
        lineas.append(json.dumps({"__REALTIME_TIMESTAMP": f"{(base - 2) * 1_000_000}",
                                  "MESSAGE": "Failed password for root from 10.0.2.20 port 5555 ssh2"}))
        MUESTRA.write_text("\n".join(lineas) + "\n", encoding="utf-8")
        print(f"{MUESTRA}: {len(lineas)} eventos")

        print("\n=== 2. Autotest ===")
        autotest()

        print("\n=== 3. Alertas que se van a enviar (sin enviar) ===")
        ESTADO.write_text('{"ips":{}}', encoding="utf-8")
        analiza(lineas, dry=True)

        print(f"\n=== 4. Envío real (bloqueo de demostración en la tabla inet {TABLA}) ===")
        ESTADO.write_text('{"ips":{}}', encoding="utf-8")
        n, _ = analiza(lineas, dry=False)
        print(f"Resumen: {n} alerta(s) enviada(s)")

        print("\n=== 5. Estado antiduplicados ===")
        print(json.dumps(carga_estado(), indent=2, ensure_ascii=False))

        print("\n=== 6. Repetición inmediata (debe salir 0 enviadas) ===")
        n, omitidas = analiza(lineas, dry=False)
        print(f"Resumen: {n} alerta(s) enviada(s), {omitidas} omitida(s) por enfriamiento")
    finally:
        print("\n=== 7. Limpieza de la demo ===")
        _nft("delete", "table", "inet", TABLA)
        for ip in ("10.0.2.24", "10.0.2.23"):  # por si se usó el respaldo de iptables
            desbloquea_ip(ip)
        print(f"tabla inet {TABLA} eliminada; tus bloqueos reales siguen intactos")
        ESTADO, LOG, TABLA, BLOQUEAR, SI, ips_locales, carga_lista_blanca = guardado
    print(f"\nListo. Log de la demo: {tmp}/alertas.log. Canal: {CANAL or '(sin canal, modo seco)'}")
    return 0


def _lineas_journal_vivo():
    """Sigue journalctl -f; produce None cada segundo sin datos para poder analizar en silencio."""
    p = subprocess.Popen(_cmd_journal("-f", "--since", f"-{VENTANA_MIN} min"),
                         stdout=subprocess.PIPE, text=True, errors="replace")
    cola = queue.Queue(maxsize=10000)

    def lector():
        for linea in p.stdout:
            cola.put(linea)
        cola.put(None)

    threading.Thread(target=lector, daemon=True).start()
    while True:
        try:
            linea = cola.get(timeout=1)
        except queue.Empty:
            yield None
            continue
        if linea is None:
            log(f"ERROR journalctl -f terminó con {p.wait()}")
            return
        yield linea


def _lineas_fichero_vivo(ruta: Path):
    with ruta.open("r", encoding="utf-8", errors="replace") as f:
        f.seek(0, os.SEEK_END)
        while True:
            linea = f.readline()
            if linea:
                yield linea
            else:
                time.sleep(0.5)
                yield None


def vigila(fuente, journal: bool = True) -> int:
    """Bucle del modo continuo. Analiza como mucho cada THROTTLE segundos, también
    cuando dejan de llegar líneas: una ráfaga seguida de silencio no se escapa."""
    ultimo = ultimo_mant = 0.0
    ultimo_resumen = time.time()
    pendiente = False
    buffer = deque(maxlen=20000)  # solo eventos de autenticación, no el ruido de sshd
    for linea in fuente:
        if linea is not None and parsea(linea, 0) is not None:
            buffer.append(linea)
            pendiente = True
        ahora = time.time()
        if pendiente and ahora - ultimo >= THROTTLE:
            ultimo, pendiente = ahora, False
            analiza(list(buffer), dry=DRY)
        if ahora - ultimo_mant >= 60:
            ultimo_mant = ahora
            mantenimiento(DRY)
        if RESUMEN_MIN > 0 and ahora - ultimo_resumen >= RESUMEN_MIN * 60:
            ultimo_resumen = ahora
            resumen(None if journal else list(buffer))
    return 1  # la fuente se cortó: código de error para que systemd lo reinicie


def _entero(cfg: dict, clave: str) -> int:
    try:
        return int(str(cfg[clave]).strip())
    except ValueError:
        sys.exit(f"{CONF}: {clave} debe ser un número entero (vale {cfg[clave]!r})")


def _argumentos(cfg: dict):
    p = argparse.ArgumentParser(
        prog="vigia_ssh.py",
        description="Detector de fuerza bruta SSH con alertas por webhook y bloqueo opcional.",
        epilog=f"Configuración: {CONF} (la línea de órdenes manda sobre el fichero).")
    p.add_argument("-u", "--umbral", type=int, default=_entero(cfg, "UMBRAL"), metavar="N",
                   help="fallos por IP para alertar (def. %(default)s)")
    p.add_argument("-w", "--ventana", type=int, default=_entero(cfg, "VENTANA_MIN"), metavar="MIN",
                   help="ventana de análisis en minutos (def. %(default)s)")
    p.add_argument("-e", "--enfriamiento", type=int, default=_entero(cfg, "ENFRIAMIENTO"), metavar="SEG",
                   help="silencio por IP tras alertar, en segundos (def. %(default)s)")
    p.add_argument("-c", "--canal", default=cfg["CANAL"], metavar="URL",
                   help="webhook del canal (mejor en el fichero: en la línea de órdenes lo ve 'ps')")
    p.add_argument("--conf", type=Path, default=CONF, metavar="RUTA", help="fichero de configuración")
    p.add_argument("-f", dest="fichero", type=Path, metavar="FICHERO", help="analiza un JSON Lines (una pasada)")
    p.add_argument("-F", dest="seguir_fichero", type=Path, metavar="FICHERO", help="sigue un JSON Lines en vivo")
    p.add_argument("-C", "--continuo", action="store_true", help="sigue journalctl -f")
    p.add_argument("-B", "--bloquear", action="store_true", help="bloquea con nftables (o iptables)")
    p.add_argument("-s", "--si", action="store_true", help="bloquea sin pedir confirmación")
    p.add_argument("-b", "--bloqueo-min-sev", default=cfg["BLOQUEO_MIN_SEV"], choices=list(PESO),
                   help="severidad mínima para bloquear (def. %(default)s)")
    p.add_argument("-r", "--resumen", type=int, default=_entero(cfg, "RESUMEN_MIN"), metavar="MIN",
                   help="resumen cada MIN minutos, 0 = nunca (def. %(default)s)")
    p.add_argument("-d", "--desbloqueo", type=int, default=_entero(cfg, "DESBLOQUEO_MIN"), metavar="MIN",
                   help="el bloqueo caduca a los MIN minutos, 0 = nunca (def. %(default)s)")
    p.add_argument("-n", "--dry-run", action="store_true", help="imprime las alertas; no envía ni bloquea")
    p.add_argument("-E", "--estado", action="store_true", help="muestra el estado y las IPs bloqueadas")
    p.add_argument("-R", "--reset", action="store_true", help="vacía el estado antiduplicados")
    p.add_argument("-L", "--limpia-lab", action="store_true", dest="limpia_lab",
                   help="laboratorio: desbloquea todas las IPs, vacía el estado y el log")
    p.add_argument("-D", "--desbloquear", metavar="IP", help="desbloquea una IP")
    p.add_argument("-t", "--autotest", action="store_true", help="autotest sin red ni root")
    p.add_argument("--demo", action="store_true", help="demostración completa y autocontenida")
    p.add_argument("-V", "--version", action="version", version=f"vigia_ssh {VERSION}")
    return p.parse_args()


def main() -> int:
    global UMBRAL, VENTANA_MIN, ENFRIAMIENTO, RESUMEN_MIN, DESBLOQUEO_MIN
    global BLOQUEO_MIN_SEV, CANAL, THROTTLE, UNIDADES, BLOQUEAR, SI, DRY
    global CONF, ESTADO, LOG, LOCK

    previo = argparse.ArgumentParser(add_help=False)
    previo.add_argument("--conf", type=Path)
    conocidos, _ = previo.parse_known_args()
    if conocidos.conf:
        CONF = conocidos.conf

    cfg = carga_conf()
    a = _argumentos(cfg)

    UMBRAL, VENTANA_MIN = a.umbral, a.ventana
    ENFRIAMIENTO, RESUMEN_MIN = a.enfriamiento, a.resumen
    DESBLOQUEO_MIN, BLOQUEO_MIN_SEV = a.desbloqueo, a.bloqueo_min_sev
    CANAL, THROTTLE = a.canal, _entero(cfg, "THROTTLE")
    UNIDADES = str(cfg["UNIDADES"]).split() or ["ssh"]
    BLOQUEAR, SI, DRY = a.bloquear, a.si, a.dry_run

    if UMBRAL <= 0 or VENTANA_MIN <= 0 or THROTTLE <= 0:
        sys.exit("UMBRAL, VENTANA_MIN y THROTTLE deben ser > 0")
    if BLOQUEO_MIN_SEV not in PESO:
        sys.exit(f"BLOQUEO_MIN_SEV inválida: {BLOQUEO_MIN_SEV!r} (media, alta o critica)")
    if min(ENFRIAMIENTO, RESUMEN_MIN, DESBLOQUEO_MIN) < 0:
        sys.exit("ENFRIAMIENTO, RESUMEN_MIN y DESBLOQUEO_MIN no pueden ser negativos")
    if ENFRIAMIENTO < VENTANA_MIN * 60:
        print(f"aviso: ENFRIAMIENTO ({ENFRIAMIENTO}s) es menor que la ventana ({VENTANA_MIN * 60}s); "
              "una misma ráfaga puede alertar dos veces", file=sys.stderr)

    for d in (ESTADO.parent, LOG.parent, LOCK.parent):
        d.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not ESTADO.exists():
        ESTADO.write_text('{"ips":{}}', encoding="utf-8")

    if a.estado:
        st = carga_estado()
        st["bloqueadas_nft"] = bloqueadas_actuales()
        print(json.dumps(st, indent=2, ensure_ascii=False))
        return 0
    if a.reset:
        ESTADO.write_text('{"ips":{}}', encoding="utf-8")
        print("estado vaciado")
        return 0
    if a.limpia_lab:
        for conjunto in ("bloqueadas", "bloqueadas6"):
            _nft("flush", "set", "inet", TABLA, conjunto)  # solo la tabla de vigia
        ESTADO.write_text('{"ips":{}}', encoding="utf-8")
        try:
            LOG.write_text("", encoding="utf-8")
        except OSError as exc:
            print(f"no se pudo vaciar el log {LOG}: {exc}", file=sys.stderr)
        print("laboratorio limpio: IPs desbloqueadas, estado y log vacíos")
        return 0
    if a.desbloquear:
        ip = normaliza_ip(a.desbloquear.strip())
        if ip is None:
            sys.exit(f"no es una IP válida: {a.desbloquear!r}")
        print(f"{ip} desbloqueada" if desbloquea_ip(ip) else f"{ip} no estaba bloqueada")
        return 0
    if a.autotest:
        return autotest()
    if a.demo:
        return demo()

    if DRY:
        # Un ensayo no deja huella: trabaja sobre una copia del estado y con su propio
        # log. Si escribiera en el estado real, el servicio daría esas IPs por
        # "ya alertadas" y no avisaría ni bloquearía durante el enfriamiento. Con su
        # propio cerrojo, además, se puede ensayar aunque el servicio esté en marcha.
        tmp = Path(tempfile.mkdtemp(prefix="vigia-ensayo-"))
        atexit.register(shutil.rmtree, tmp, ignore_errors=True)
        shutil.copy(ESTADO, tmp / "estado.json")
        ESTADO, LOG, LOCK = tmp / "estado.json", tmp / "alertas.log", tmp / "vigia.lock"

    if not CANAL and not DRY:
        sys.exit("falta CANAL en la configuración o -c URL (o usa -n)")
    if CANAL and not CANAL.startswith(("http://", "https://")):
        sys.exit("CANAL debe empezar por http:// o https://")
    if CANAL.startswith("http://") and urllib.parse.urlsplit(CANAL).hostname not in ("localhost", "127.0.0.1", "::1"):
        print("aviso: el webhook va por http://, sin cifrar", file=sys.stderr)
    if a.seguir_fichero and not a.seguir_fichero.is_file():
        sys.exit(f"no existe {a.seguir_fichero}")

    with LOCK.open("w") as cerrojo:
        try:
            fcntl.flock(cerrojo, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print("ya hay una instancia en marcha", file=sys.stderr)
            return 0
        try:
            if a.seguir_fichero:
                return vigila(_lineas_fichero_vivo(a.seguir_fichero), journal=False)
            if a.continuo:
                return vigila(_lineas_journal_vivo())
            reintenta_pendientes(DRY)
            if a.fichero:
                analiza(a.fichero.read_text(encoding="utf-8", errors="replace").splitlines(), dry=DRY)
            else:
                analiza(lineas_journal(), dry=DRY)
        except KeyboardInterrupt:
            print("\nparado", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
