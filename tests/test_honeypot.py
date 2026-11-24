#!/usr/bin/env python3
"""Pruebas del honeypot, sin root. Se saltan si no está paramiko."""
import importlib.util
import io
import json
import os
import socket
import stat
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path

try:
    import paramiko
except ImportError:  # pragma: no cover
    paramiko = None

RUTA = Path(__file__).resolve().parents[1] / "bin" / "honeypot.py"


def carga():
    spec = importlib.util.spec_from_file_location("honeypot", RUTA)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@unittest.skipIf(paramiko is None, "paramiko no está instalado")
class TestRegistro(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.hp = carga()
        self.hp.LOG = os.path.join(self.tmp.name, "ssh_honeypot.jsonl")

    def tearDown(self):
        if self.hp._fd_log is not None:
            os.close(self.hp._fd_log)
        self.tmp.cleanup()

    def registra(self, *args):
        pantalla = io.StringIO()
        with redirect_stdout(pantalla):
            self.hp.registra(*args)
        return pantalla.getvalue()

    def lineas(self):
        with open(self.hp.LOG, encoding="utf-8") as f:
            return [json.loads(x) for x in f]

    def test_log_privado_aunque_ya_existiera_con_644(self):
        Path(self.hp.LOG).touch(mode=0o644)
        os.chmod(self.hp.LOG, 0o644)
        self.registra("203.0.113.5", "admin", "clave-de-prueba")
        self.assertEqual(stat.S_IMODE(os.stat(self.hp.LOG).st_mode), 0o600)

    def test_escapa_secuencias_de_terminal(self):
        salida = self.registra("203.0.113.5", "\x1b[2J\x1b]0;hola\x07falso", "x")
        self.assertNotIn("\x1b[2J", salida)
        self.assertNotIn("\x1b]0;", salida)
        self.assertIn("\\x1b[2J", salida)

    def test_la_contrasena_no_sale_por_pantalla(self):
        salida = self.registra("203.0.113.5", "admin", "clave-de-prueba")
        self.assertNotIn("clave-de-prueba", salida)
        self.assertIn("<15 car.>", salida)
        self.assertEqual(self.lineas()[0]["contrasena"], "clave-de-prueba")

    def test_contrasena_no_utf8_se_registra(self):
        self.registra("203.0.113.5", "root", b"\xff\xfe-no-utf8")
        self.assertEqual(self.lineas()[0]["contrasena"], "\\xff\\xfe-no-utf8")

    def test_campos_acotados(self):
        self.registra("203.0.113.5", "u" * 5000, "p" * 5000)
        reg = self.lineas()[0]
        self.assertLessEqual(len(reg["usuario"]), self.hp.MAX_CAMPO)
        self.assertLessEqual(len(reg["contrasena"]), self.hp.MAX_CAMPO)

    def test_severidad_baja_alta_por_numero_de_intentos(self):
        self.hp.UMBRAL = 5
        for i in range(5):
            self.registra("203.0.113.9", "root", f"p{i}")
        self.assertEqual(self.lineas()[-1]["severidad"], "baja")   # 5º intento: aún baja
        self.registra("203.0.113.9", "root", "p5")
        self.assertEqual(self.lineas()[-1]["severidad"], "alta")   # 6º: pasa del umbral
        # otra IP empieza de cero
        self.registra("198.51.100.7", "root", "x")
        self.assertEqual(self.lineas()[-1]["severidad"], "baja")

    def test_severidad_critica_si_acierta_la_clave(self):
        self.hp.CLAVE_BUENA = "Lab-2026x"
        self.registra("203.0.113.9", "prueba", "Lab-2026x")
        self.assertEqual(self.lineas()[-1]["severidad"], "critica")

    def test_solo_la_clave_buena_concede_acceso(self):
        self.hp.CLAVE_BUENA = "Lab-2026x"
        puerta = self.hp.Puerta("203.0.113.9")
        self.assertEqual(puerta.check_auth_password("prueba", "Lab-2026x"),
                         paramiko.AUTH_SUCCESSFUL)
        self.assertEqual(puerta.check_auth_password("prueba", "123456"),
                         paramiko.AUTH_FAILED)


@unittest.skipIf(paramiko is None, "paramiko no está instalado")
class TestConcurrencia(unittest.TestCase):
    def test_una_conexion_abierta_no_bloquea_a_las_demas(self):
        tmp = tempfile.mkdtemp()
        hp = carga()
        hp.LOG = os.path.join(tmp, "ssh_honeypot.jsonl")
        hp.print = lambda *a, **k: None          # sin ruido en la salida de los tests
        hp.suelta_privilegios = lambda: None     # si los tests corren como root, no soltar
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            hp.PUERTO = s.getsockname()[1]
        threading.Thread(target=hp.main, daemon=True).start()
        deadline = time.time() + 15
        while time.time() < deadline:
            try:
                socket.create_connection(("127.0.0.1", hp.PUERTO), timeout=1).close()
                break
            except OSError:
                time.sleep(0.2)

        ocupada = paramiko.Transport(("127.0.0.1", hp.PUERTO))
        ocupada.start_client(timeout=10)  # se queda abierta sin autenticarse
        try:
            segunda = paramiko.Transport(("127.0.0.1", hp.PUERTO))
            segunda.banner_timeout = 5
            segunda.start_client(timeout=5)
            self.assertTrue(segunda.remote_version.startswith("SSH-2.0-OpenSSH"))
            with self.assertRaises(paramiko.AuthenticationException):
                segunda.auth_password("root", "1234")
            segunda.close()
        finally:
            ocupada.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
