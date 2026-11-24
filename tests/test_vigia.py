#!/usr/bin/env python3
"""Pruebas del núcleo de análisis, sin root y sin red."""
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

RUTA = Path(__file__).resolve().parents[1] / "bin" / "vigia_ssh.py"
spec = importlib.util.spec_from_file_location("vigia", RUTA)
vigia = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vigia)


def linea(msg, segundos=10):
    ts = (int(time.time()) - segundos) * 1_000_000
    return json.dumps({"__REALTIME_TIMESTAMP": str(ts), "MESSAGE": msg})


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        raiz = Path(self.tmp.name)
        vigia.ESTADO = raiz / "estado.json"
        vigia.LISTA_BLANCA = raiz / "blanca.json"
        vigia.LOG = raiz / "alertas.log"
        vigia.ESTADO.write_text('{"ips":{}}')
        vigia.LISTA_BLANCA.write_text('["10.0.2.20"]')
        vigia.UMBRAL = 5
        vigia.VENTANA_MIN = 5
        vigia.ENFRIAMIENTO = 600
        vigia.RESUMEN_MIN = 0
        vigia.DESBLOQUEO_MIN = 0
        vigia.BLOQUEO_MIN_SEV = "alta"
        vigia.CANAL = ""
        vigia.THROTTLE = 10
        vigia.BLOQUEAR = False
        vigia.SI = True
        vigia.DRY = True
        self._ips_original = vigia.ips_locales
        vigia.ips_locales = lambda: set()

    def tearDown(self):
        vigia.ips_locales = self._ips_original
        self.tmp.cleanup()

    def ejecuta(self, lineas, dry=True):
        salida = io.StringIO()
        with redirect_stdout(salida), redirect_stderr(io.StringIO()):
            n, omitidas = vigia.analiza(lineas, dry=dry)
        return n, omitidas, salida.getvalue()

    def alertas(self, salida):
        return [json.loads(x) for x in salida.splitlines() if x.startswith("{")]

    def fallos(self, ip, n, usuario="root"):
        return [linea(f"Failed password for invalid user {usuario} from {ip} port 5000 ssh2", i)
                for i in range(n)]


class TestUmbral(Base):
    def test_bajo_umbral_no_alerta(self):
        n, _, _ = self.ejecuta(self.fallos("10.0.2.24", 4))
        self.assertEqual(n, 0)

    def test_umbral_alerta(self):
        n, _, salida = self.ejecuta(self.fallos("10.0.2.24", 5))
        self.assertEqual(n, 1)
        self.assertIn('"severidad": "media"', salida)

    def test_doble_umbral_es_alta(self):
        n, _, salida = self.ejecuta(self.fallos("10.0.2.24", 10))
        self.assertEqual(n, 1)
        self.assertIn('"severidad": "alta"', salida)

    def test_acceso_conseguido_es_critica(self):
        lineas = self.fallos("10.0.2.24", 6)
        lineas.append(linea("Accepted password for kali from 10.0.2.24 port 6000 ssh2", 1))
        n, _, salida = self.ejecuta(lineas)
        self.assertEqual(n, 1)
        self.assertIn('"severidad": "critica"', salida)

    def test_acceso_antes_de_los_fallos_no_es_critica(self):
        lineas = [linea("Accepted password for kali from 10.0.2.24 port 6000 ssh2", 60)]
        lineas += self.fallos("10.0.2.24", 6)
        _, _, salida = self.ejecuta(lineas)
        self.assertEqual(self.alertas(salida)[0]["severidad"], "media")


class TestFiltros(Base):
    def test_lista_blanca_silencia(self):
        n, omitidas, _ = self.ejecuta(self.fallos("10.0.2.20", 20))
        self.assertEqual(n, 0)
        self.assertGreaterEqual(omitidas, 1)

    def test_ip_local_se_silencia(self):
        vigia.ips_locales = lambda: {"10.0.2.24"}
        n, omitidas, _ = self.ejecuta(self.fallos("10.0.2.24", 20))
        self.assertEqual(n, 0)
        self.assertGreaterEqual(omitidas, 1)

    def test_loopback_nunca_alerta(self):
        for ip in ("127.0.0.1", "::1"):
            n, _, _ = self.ejecuta(self.fallos(ip, 20))
            self.assertEqual(n, 0, ip)

    def test_lista_blanca_acepta_redes(self):
        vigia.LISTA_BLANCA.write_text('["192.168.56.0/24", "2001:db8::/32"]')
        self.assertEqual(self.ejecuta(self.fallos("192.168.56.77", 20))[0], 0)
        self.assertEqual(self.ejecuta(self.fallos("2001:db8::66", 20))[0], 0)
        self.assertEqual(self.ejecuta(self.fallos("192.168.57.1", 20))[0], 1)

    def test_entrada_invalida_en_lista_blanca_no_rompe(self):
        vigia.LISTA_BLANCA.write_text('["no-es-una-ip", "10.0.2.20"]')
        self.assertEqual(self.ejecuta(self.fallos("10.0.2.20", 20))[0], 0)

    def test_enfriamiento_no_duplica(self):
        self.ejecuta(self.fallos("10.0.2.24", 6))
        n, omitidas, _ = self.ejecuta(self.fallos("10.0.2.24", 6))
        self.assertEqual(n, 0)
        self.assertEqual(omitidas, 1)

    def test_rafaga_que_pasa_de_media_a_alta_da_una_sola_alerta_y_bloquea(self):
        vigia.BLOQUEAR, vigia.DRY = True, False
        lineas = self.fallos("10.0.2.24", 6)
        with mock.patch.object(vigia, "bloquea_ip", return_value="nft") as bloquea_ip:
            self.assertEqual(self.ejecuta(lineas, dry=False)[0], 1)              # media, sin bloqueo
            bloquea_ip.assert_not_called()
            n, _, _ = self.ejecuta(lineas + self.fallos("10.0.2.24", 6), dry=False)  # ya son 12
        self.assertEqual(n, 0)
        bloquea_ip.assert_called_once_with("10.0.2.24")
        self.assertEqual(vigia.carga_estado()["ips"]["10.0.2.24"]["severidad"], "alta")

    def test_si_sube_la_severidad_se_avisa_aunque_haya_enfriamiento(self):
        lineas = self.fallos("10.0.2.24", 6)
        self.assertEqual(self.ejecuta(lineas)[0], 1)          # media
        lineas.append(linea("Accepted password for kali from 10.0.2.24 port 6000 ssh2", 0))
        n, _, salida = self.ejecuta(lineas)                     # entra: critica
        self.assertEqual((n, self.alertas(salida)[0]["severidad"]), (1, "critica"))
        self.assertEqual(self.ejecuta(lineas)[0], 0)          # la misma critica: duplicada

    def test_usuarios_sin_duplicados(self):
        lineas = (self.fallos("10.0.2.24", 3, "root")
                  + self.fallos("10.0.2.24", 3, "admin")
                  + self.fallos("10.0.2.24", 2, "root"))
        _, _, salida = self.ejecuta(lineas)
        datos = self.alertas(salida)[0]
        self.assertEqual(datos["usuarios"], ["admin", "root"])
        self.assertEqual(datos["intentos"], 8)


class TestParseo(unittest.TestCase):
    def test_extrae_campos(self):
        ev = vigia.parsea(linea("Failed password for invalid user root from 10.0.2.24 port 1 ssh2"), 0)
        self.assertEqual(ev["ip"], "10.0.2.24")
        self.assertEqual(ev["usuario"], "root")

    def test_ignora_ruido(self):
        self.assertIsNone(vigia.parsea(linea("Connection closed by 10.0.2.24 port 1"), 0))
        self.assertIsNone(vigia.parsea("no es json", 0))

    def test_descarta_fuera_de_ventana(self):
        viejo = json.dumps({"__REALTIME_TIMESTAMP": "1000",
                            "MESSAGE": "Failed password for root from 10.0.2.24 port 1 ssh2"})
        self.assertIsNone(vigia.parsea(viejo, 2_000_000))

    def test_ipv6(self):
        ev = vigia.parsea(linea("Failed password for root from 2001:db8::66 port 1 ssh2"), 0)
        self.assertEqual(ev["ip"], "2001:db8::66")


class TestInyeccion(Base):
    """El usuario lo elige el atacante y sshd lo registra con espacios incluidos."""

    def test_from_en_el_usuario_no_cambia_la_ip(self):
        msg = "Failed password for invalid user x from 10.0.2.50 from 203.0.113.9 port 4242 ssh2"
        ev = vigia.parsea(linea(msg), 0)
        self.assertEqual(ev["ip"], "203.0.113.9")
        self.assertEqual(ev["usuario"], "x from 10.0.2.50")

    def test_cola_completa_inventada_en_el_usuario(self):
        msg = ("Failed password for invalid user a from 10.0.2.50 port 1 ssh2 "
               "from 203.0.113.9 port 4242 ssh2")
        self.assertEqual(vigia.parsea(linea(msg), 0)["ip"], "203.0.113.9")

    def test_no_se_puede_hacer_bloquear_a_un_tercero(self):
        lineas = [linea("Failed password for invalid user x from 10.0.2.50 "
                        f"from 203.0.113.9 port {4000 + i} ssh2", i) for i in range(12)]
        _, _, salida = self.ejecuta(lineas)
        self.assertEqual([a["ip"] for a in self.alertas(salida)], ["203.0.113.9"])

    def test_usuarios_con_espacios_o_vacios_cuentan(self):
        for usuario in ("john smith", ""):
            ev = vigia.parsea(linea(f"Failed password for invalid user {usuario} from 203.0.113.9 port 1 ssh2"), 0)
            self.assertEqual((ev["ip"], ev["usuario"]), ("203.0.113.9", usuario))

    def test_pam_tambien_va_anclado_al_final(self):
        msg = "error: PAM: Authentication failure for illegal user x from 10.0.2.50 from 203.0.113.9"
        self.assertEqual(vigia.parsea(linea(msg), 0)["ip"], "203.0.113.9")


class TestKeyboardInteractive(Base):
    def test_fallo_pam_de_usuario_valido_cuenta(self):
        ev = vigia.parsea(linea("error: PAM: Authentication failure for kali from 203.0.113.9"), 0)
        self.assertEqual(ev["tipo"], "fallo")

    def test_no_cuenta_doble(self):
        lineas = []
        for i in range(5):
            lineas.append(linea("error: PAM: Authentication failure for illegal user x from 203.0.113.9", i))
            lineas.append(linea(f"Failed keyboard-interactive/pam for invalid user x from 203.0.113.9 "
                                f"port {4000 + i} ssh2", i))
        _, _, salida = self.ejecuta(lineas)
        self.assertEqual(self.alertas(salida)[0]["intentos"], 5)

    def test_acceso_keyboard_interactive_es_critica(self):
        lineas = self.fallos("203.0.113.9", 6)
        lineas.append(linea("Accepted keyboard-interactive/pam for kali from 203.0.113.9 port 1 ssh2", 0))
        _, _, salida = self.ejecuta(lineas)
        self.assertEqual(self.alertas(salida)[0]["severidad"], "critica")


class TestAlerta(Base):
    def test_alerta_sigue_el_contrato_del_ejercicio(self):
        lineas = self.fallos("203.0.113.9", 4, "root") + self.fallos("203.0.113.9", 3, "admin")
        _, _, salida = self.ejecuta(lineas)
        a = self.alertas(salida)[0]
        self.assertEqual(list(a), ["tipo", "host", "ts", "ip", "intentos", "ventana_min",
                                   "usuarios", "severidad"])
        self.assertEqual(a["usuarios"], ["admin", "root"])

    def test_muchos_usuarios_caben_en_discord_y_el_json_los_lleva_todos(self):
        lineas = []
        for i in range(80):
            lineas += self.fallos("203.0.113.9", 1, f"u{i:02d}_" + "A" * 96)
        _, _, salida = self.ejecuta(lineas)
        a = self.alertas(salida)[0]
        self.assertEqual(len(a["usuarios"]), 80)
        embed = vigia.formato_discord(a)["embeds"][0]
        usuarios = embed["fields"][-1]["value"]
        self.assertLessEqual(len(usuarios), vigia.LIMITE_CAMPO)
        self.assertIn("más", usuarios)
        self.assertTrue(usuarios.endswith("```"))
        self.assertEqual(embed["fields"][-1]["name"], "Usuarios (80)")

    def test_discord_tarjeta_con_color_y_sin_menciones(self):
        _, _, salida = self.ejecuta(self.fallos("203.0.113.9", 12, "a```@everyone"))
        cuerpo = vigia.formato_discord(self.alertas(salida)[0])
        self.assertEqual(cuerpo["allowed_mentions"], {"parse": []})
        embed = cuerpo["embeds"][0]
        self.assertEqual(embed["color"], vigia.COLOR_DISCORD["alta"])
        self.assertIn("ALTA", embed["title"])
        usuarios = embed["fields"][-1]["value"]
        self.assertEqual(usuarios.count("```"), 2)  # el usuario no puede cerrar el bloque

    def test_discord_resumen(self):
        cuerpo = vigia.formato_discord({
            "tipo": "resumen_ssh", "host": "h", "ts": "2026-01-01T00:00:00Z", "periodo_min": 5,
            "fallos": 9, "top_ips": [{"ip": "203.0.113.9", "intentos": 9}],
            "top_usuarios": [{"usuario": "x" * 60, "intentos": 9}]})
        embed = cuerpo["embeds"][0]
        self.assertIn("Resumen", embed["title"])
        self.assertIn("203.0.113.9 (9)", embed["fields"][2]["value"])
        self.assertIn("(9)", embed["fields"][3]["value"])  # el recorte no se come el contador

    def test_discord_por_host_y_no_por_subcadena(self):
        self.assertTrue(vigia.es_discord("https://discord.com/api/webhooks/1/x"))
        self.assertTrue(vigia.es_discord("https://canary.discord.com/api/webhooks/1/x"))
        self.assertFalse(vigia.es_discord("https://ejemplo.net/discord.com/x"))


class TestBloqueo(Base):
    def setUp(self):
        super().setUp()
        vigia.BLOQUEAR = True
        vigia.DRY = False
        vigia.CANAL = "http://127.0.0.1:9/hook"

    def test_bloquea_aunque_falle_el_webhook(self):
        with mock.patch.object(vigia, "envia", return_value=False), \
             mock.patch.object(vigia, "bloquea_ip", return_value="nft") as bloquea_ip:
            self.ejecuta(self.fallos("203.0.113.9", 12), dry=False)
        bloquea_ip.assert_called_once_with("203.0.113.9")
        st = vigia.carga_estado()
        self.assertTrue(st["ips"]["203.0.113.9"]["bloqueada"])
        self.assertEqual(st["pendientes"][0]["ip"], "203.0.113.9")

    def test_reintenta_y_vacia_la_cola(self):
        vigia.encola({"tipo": "alerta_ssh", "ip": "203.0.113.9"})
        with mock.patch.object(vigia, "envia", return_value=True):
            vigia.reintenta_pendientes()
        self.assertEqual(vigia.carga_estado()["pendientes"], [])

    def test_si_falla_el_bloqueo_no_se_marca_como_bloqueada(self):
        with mock.patch.object(vigia, "envia", return_value=True), \
             mock.patch.object(vigia, "bloquea_ip", return_value=None):
            self.ejecuta(self.fallos("203.0.113.9", 12), dry=False)
        self.assertFalse(vigia.carga_estado()["ips"]["203.0.113.9"].get("bloqueada", False))

    def test_sin_terminal_no_bloquea(self):
        vigia.SI = False
        with mock.patch("builtins.open", side_effect=OSError("sin tty")), redirect_stderr(io.StringIO()):
            self.assertFalse(vigia.confirma("203.0.113.9", "alta"))

    def test_nunca_bloquea_loopback(self):
        with mock.patch.object(vigia, "bloquea_ip") as bloquea_ip:
            self.assertFalse(vigia.bloquea("127.0.0.1", "critica", dry=False))
        bloquea_ip.assert_not_called()

    def test_bloqueadas_actuales_lee_el_json_de_nft(self):
        salida = json.dumps({"nftables": [
            {"metainfo": {"version": "1.0.9"}},
            {"set": {"family": "inet", "name": "bloqueadas", "table": "vigia", "type": "ipv4_addr",
                     "elem": [{"elem": {"val": "203.0.113.1", "timeout": 1800}}, "203.0.113.2"]}}]})
        hecho = vigia.subprocess.CompletedProcess([], 0, salida, "")
        with mock.patch.object(vigia.shutil, "which", return_value="/usr/sbin/nft"), \
             mock.patch.object(vigia, "_nft", return_value=hecho):
            self.assertEqual(vigia.bloqueadas_actuales(), ["203.0.113.1", "203.0.113.2"] * 2)


class TestContinuo(Base):
    def test_rafaga_seguida_de_silencio_se_analiza(self):
        vigia.THROTTLE = 0.3

        def fuente():
            yield from self.fallos("203.0.113.9", 20)  # todo en el mismo instante
            for _ in range(4):  # luego silencio: solo "ticks" sin líneas
                time.sleep(0.15)
                yield None

        salida = io.StringIO()
        with redirect_stdout(salida), redirect_stderr(io.StringIO()):
            vigia.vigila(fuente(), journal=False)
        self.assertEqual(len(self.alertas(salida.getvalue())), 1)


class TestResumen(Base):
    def test_resumen_cubre_su_periodo_y_no_la_ventana(self):
        vigia.RESUMEN_MIN = 60
        lineas = [linea(f"Failed password for root from 203.0.113.9 port {i} ssh2", 30 * 60) for i in range(3)]
        salida = io.StringIO()
        with redirect_stdout(salida):
            vigia.resumen(lineas)
        datos = json.loads(salida.getvalue())
        self.assertEqual((datos["fallos"], datos["periodo_min"]), (3, 60))


class TestAutotest(Base):
    def test_autotest_no_toca_el_estado_ni_el_log_reales(self):
        real = '{"ips": {"198.51.100.7": {"ultima": 1, "bloqueada": true}}}'
        vigia.ESTADO.write_text(real)
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(vigia.autotest(), 0)
        self.assertEqual(vigia.ESTADO.read_text(), real)
        self.assertFalse(vigia.LOG.exists())


class TestLineaDeOrdenes(unittest.TestCase):
    def ejecuta(self, *args):
        self.tmp = tempfile.TemporaryDirectory()
        raiz = Path(self.tmp.name)
        self.estado = raiz / "estado.json"
        self.log = raiz / "alertas.log"
        self.estado.write_text('{"ips":{}}')
        self.fichero = raiz / "f.jsonl"
        self.fichero.write_text("\n".join(
            linea(f"Failed password for root from 203.0.113.40 port {i} ssh2", i) for i in range(12)) + "\n")
        env = {**os.environ, "VIGIA_CONF": str(raiz / "no.conf"), "VIGIA_ESTADO": str(self.estado),
               "VIGIA_LOG": str(self.log), "VIGIA_LOCK": str(raiz / "vigia.lock"),
               "VIGIA_LISTA_BLANCA": str(raiz / "blanca.json")}
        args = [str(self.fichero) if a == "FICHERO" else a for a in args]
        return subprocess.run([sys.executable, str(RUTA), *args], env=env,
                              capture_output=True, text=True, timeout=60)

    def tearDown(self):
        self.tmp.cleanup()

    def test_ensayo_no_toca_el_estado_ni_el_log_reales(self):
        r = self.ejecuta("-f", "FICHERO", "-n")
        self.assertIn('"alerta_ssh"', r.stdout)
        self.assertEqual(json.loads(self.estado.read_text())["ips"], {})
        self.assertFalse(self.log.exists())

    def test_desbloquear_rechaza_lo_que_no_es_una_ip(self):
        r = self.ejecuta("-D", "1.1.1.1 }; flush ruleset")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("no es una IP válida", r.stderr)

    def test_ayuda_y_version(self):
        self.assertIn("--bloquear", self.ejecuta("-h").stdout)
        self.assertIn("vigia_ssh", self.ejecuta("-V").stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestVerAlertas(unittest.TestCase):
    def test_tabla_legible_y_sin_secuencias_del_atacante(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "alertas.log"
            alerta = {"tipo": "alerta_ssh", "host": "h", "ts": "2026-01-01T10:00:00Z", "ip": "203.0.113.9",
                      "intentos": 12, "ventana_min": 5, "usuarios": ["root", "x\x1b]0;hola\x07"],
                      "severidad": "alta"}
            log.write_text("2026-01-01T10:00:00Z bloqueada 203.0.113.9 con nft (severidad alta)\n"
                           f"2026-01-01T10:00:00Z {json.dumps(alerta)}\n", encoding="utf-8")
            r = subprocess.run(["bash", str(RUTA.with_name("ver_alertas.sh"))],
                               env={**os.environ, "VIGIA_LOG": str(log), "TZ": "UTC"},
                               capture_output=True, text=True, check=True)
        self.assertIn("2026-01-01T10:00:00Z", r.stdout)
        self.assertIn("alerta_ssh", r.stdout)
        self.assertIn("BLOQUEADA", r.stdout)
        self.assertIn("ALTA", r.stdout)
        self.assertNotIn("\x1b]0;", r.stdout)  # el título de la terminal no se toca
        self.assertNotIn("\x07", r.stdout)
