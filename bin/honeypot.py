#!/usr/bin/env python3
"""honeypot.py — Servidor SSH falso que registra usuario y contraseña.

sshd no guarda las contraseñas probadas; este señuelo sí. Escribe JSON Lines
con fecha, IP, puerto, usuario, contraseña y severidad, y pinta la línea en
color. Pensado para correr en un puerto aparte (2222) junto al sshd real.

Uso: honeypot.py [PUERTO]
  VIGIA_HONEYPOT_LOG     fichero de registro (def. /var/log/ssh_honeypot.jsonl)
  VIGIA_HONEYPOT_BANNER  versión SSH que anuncia (def. la de un OpenSSH de Ubuntu)

Si se arranca como root, abre el puerto y el registro y después baja a 'nobody':
el código que habla con el atacante nunca corre como root.
"""
import json
import logging
import os
import pwd
import socket
import sys
import threading
import time
from datetime import datetime

import paramiko

PUERTO = 2222
LOG = os.environ.get("VIGIA_HONEYPOT_LOG", "/var/log/ssh_honeypot.jsonl")
BANNER = os.environ.get("VIGIA_HONEYPOT_BANNER", "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5")
MAX_CONEXIONES = 50      # conexiones atendidas a la vez
MAX_SEGUNDOS = 60        # vida máxima de cada conexión
MAX_CAMPO = 128          # caracteres que se guardan de usuario y contraseña

# Contraseña "buena": si el atacante la acierta, habría entrado -> critica.
# Se pone en el entorno; vacía = nunca hay critica por acierto.
CLAVE_BUENA = os.environ.get("VIGIA_HONEYPOT_CLAVE", "")
UMBRAL = int(os.environ.get("VIGIA_HONEYPOT_UMBRAL", "5"))   # más de UMBRAL intentos -> alta

COLOR = {"baja": "\033[36m", "alta": "\033[91m", "critica": "\033[1;91m"}
RESET = "\033[0m"
_intentos = {}   # intentos vistos por IP

_cerrojo = threading.Lock()
_plazas = threading.BoundedSemaphore(MAX_CONEXIONES)
_fd_log = None


def texto(valor) -> str:
    """Usuario y contraseña como texto acotado (paramiko da bytes si no son UTF-8)."""
    if isinstance(valor, bytes):
        valor = valor.decode("utf-8", errors="backslashreplace")
    return str(valor)[:MAX_CAMPO]


def visible(valor: str) -> str:
    """Escapa lo no imprimible para que el atacante no mande secuencias al terminal."""
    salida = []
    for c in valor:
        o = ord(c)
        if c.isprintable():
            salida.append(c)
        elif o < 0x100:
            salida.append(f"\\x{o:02x}")
        elif o < 0x10000:
            salida.append(f"\\u{o:04x}")
        else:
            salida.append(f"\\U{o:08x}")
    return "".join(salida)


def severidad(contrasena: str, intentos: int) -> str:
    # critica: acierta la contraseña buena (habría accedido).
    # alta: pasa del umbral de intentos desde esa IP. baja: por debajo.
    if CLAVE_BUENA and contrasena == CLAVE_BUENA:
        return "critica"
    return "alta" if intentos > UMBRAL else "baja"


def abre_log() -> int:
    # 0600 al crearlo y también si ya existía (p. ej. creado por otro programa con 0644):
    # aquí hay contraseñas, a veces reales de alguien que se equivocó de puerto.
    fd = os.open(LOG, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    os.fchmod(fd, 0o600)
    return fd


def registra(ip: str, usuario, contrasena) -> None:
    global _fd_log
    usuario, contrasena = texto(usuario), texto(contrasena)
    with _cerrojo:
        _intentos[ip] = _intentos.get(ip, 0) + 1
        n = _intentos[ip]
    sev = severidad(contrasena, n)
    ahora = datetime.now().astimezone()
    reg = {"ts": ahora.isoformat(timespec="seconds"), "ip": ip, "puerto": PUERTO,
           "usuario": usuario, "contrasena": contrasena, "severidad": sev}
    linea = (json.dumps(reg, ensure_ascii=False) + "\n").encode("utf-8")
    with _cerrojo:
        if _fd_log is None:
            _fd_log = abre_log()
        os.write(_fd_log, linea)
    # La contraseña no sale por pantalla: esta salida puede acabar en el journal o en
    # un nohup.out, legibles por más gente. Completa solo está en el log 0600, que
    # enseña ver_ataques.sh.
    print(f"{ahora:%H:%M:%S} {ip:>15}:{PUERTO} usuario={visible(usuario)} "
          f"contrasena=<{len(contrasena)} car.> {COLOR[sev]}[{sev.upper()}]{RESET}", flush=True)


class Puerta(paramiko.ServerInterface):
    def __init__(self, ip):
        self.ip = ip

    def check_auth_password(self, username, password):
        try:
            registra(self.ip, username, password)
        except Exception as exc:  # un fallo al registrar no debe tumbar la conexión
            print(f"error registrando un intento de {self.ip}: {exc}", file=sys.stderr)
        # Solo la contraseña buena "accede": así hydra la marca como válida y queda como
        # critica. No se abre ninguna sesión ni shell; la conexión se cierra enseguida.
        if CLAVE_BUENA and texto(password) == CLAVE_BUENA:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"


def atiende(cliente: socket.socket, ip: str, clave) -> None:
    transporte = None
    try:
        transporte = paramiko.Transport(cliente)
        transporte.local_version = BANNER
        transporte.add_server_key(clave)
        transporte.start_server(server=Puerta(ip))
        fin = time.monotonic() + MAX_SEGUNDOS
        while transporte.is_active() and time.monotonic() < fin:
            time.sleep(0.2)
    except Exception:  # noqa: S110 (escáneres y clientes rotos cortan a medias: es lo normal)
        pass
    finally:
        if transporte is not None:
            transporte.close()
        cliente.close()
        _plazas.release()


def suelta_privilegios() -> None:
    if os.geteuid() != 0:
        return
    nadie = pwd.getpwnam("nobody")
    os.setgroups([])
    os.setgid(nadie.pw_gid)
    os.setuid(nadie.pw_uid)


def main():
    global _fd_log
    # Los escáneres cortan conexiones a medias todo el rato; que paramiko no lo pinte.
    logging.getLogger("paramiko").setLevel(logging.CRITICAL)
    clave = paramiko.RSAKey.generate(2048)
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", PUERTO))  # noqa: S104 (es un señuelo: tiene que verse desde fuera)
    srv.listen(64)
    _fd_log = abre_log()
    suelta_privilegios()
    print(f"escuchando en {PUERTO} -> {LOG} (uid {os.geteuid()})", flush=True)
    while True:
        cliente, origen = srv.accept()
        if not _plazas.acquire(blocking=False):
            cliente.close()  # demasiadas conexiones abiertas: esta se descarta
            continue
        threading.Thread(target=atiende, args=(cliente, origen[0], clave), daemon=True).start()


if __name__ == "__main__":
    if len(sys.argv) > 1:
        PUERTO = int(sys.argv[1])
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
