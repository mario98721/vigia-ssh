#!/usr/bin/env python3
"""receptor.py — recibe los webhooks de vigia_ssh.py y los muestra en un dashboard
en vivo. Solo usa la librería estándar de Python (sin Flask ni nada que instalar).

Uso:
    python3 receptor.py                 # escucha SOLO en 127.0.0.1:8000 (local)
    python3 receptor.py -p 9000         # otro puerto
    python3 receptor.py --store reg.jsonl
    python3 receptor.py --token SECRETO  # exige la cabecera X-Token (o ?token=SECRETO)
    python3 receptor.py --host 0.0.0.0 --token SECRETO   # expuesto: el token es OBLIGATORIO

Seguridad: por defecto solo escucha en localhost. Exponerlo en una interfaz de
red (--host distinto de 127.0.0.1) EXIGE --token; sin él, el receptor se niega a
arrancar. Se prefiere la cabecera X-Token a ?token= (la query puede quedar en el
historial o en logs). El POST se limita a 64 KiB y el histórico a VIGIA_RECEPTOR_MAX
registros (10000 por defecto), en memoria y en disco.

Pon el canal de vigia apuntando a este receptor y reinicia el servicio:
    sudo sed -i 's#^CANAL=.*#CANAL=http://127.0.0.1:8000/#' /etc/vigia/vigia.conf
    sudo systemctl restart vigia-ssh

Dashboard: http://localhost:8000/
(Opcional: para verlo desde fuera de la máquina, expón el puerto con ngrok u
otro túnel, usa --token y pon ese token en la URL y en CANAL.)
"""
import argparse
import hmac
import html
import json
import os
import secrets
import threading
from collections import Counter
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

SEV = ["media", "alta", "critica"]
COLOR = {"media": "#eda100", "alta": "#d95926", "critica": "#e24b4a"}

REGISTROS = []          # cada uno: {id, recibido, metodo, remoto, **payload}
LOCK = threading.Lock()
STORE = "receptor_registros.jsonl"
TOKEN = ""              # si no está vacío, se exige en cada petición
MAX_BODY = 64 * 1024    # tamaño máximo de un POST (bytes)
MAX_REGISTROS = int(os.environ.get("VIGIA_RECEPTOR_MAX", "10000"))  # tope en memoria y en disco


def carga():
    if not os.path.exists(STORE):
        return
    with open(STORE, encoding="utf-8", errors="replace") as f:
        for linea in f:
            linea = linea.strip()
            if linea:
                try:
                    REGISTROS.append(json.loads(linea))
                except ValueError:
                    pass
    if len(REGISTROS) > MAX_REGISTROS:        # recorta un histórico heredado grande
        del REGISTROS[:-MAX_REGISTROS]
        reescribe()


def reescribe():
    """Reescribe el fichero con solo los registros que quedan en memoria."""
    tmp = STORE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        for r in REGISTROS:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    os.replace(tmp, STORE)


def registra(reg):
    """Añade un registro respetando el tope de memoria y de disco."""
    with LOCK:
        REGISTROS.append(reg)
        if len(REGISTROS) > MAX_REGISTROS:    # cae el más antiguo; el fichero se reescribe acotado
            del REGISTROS[0]
            reescribe()
        else:
            with open(STORE, "a", encoding="utf-8") as f:
                f.write(json.dumps(reg, ensure_ascii=False) + "\n")


def e(x):
    return html.escape(str(x))


def hora(ts):
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ"):
        try:
            return f"{datetime.strptime(ts, fmt):%Y-%m-%d %H:%M:%S}"
        except (ValueError, TypeError):
            pass
    return e(str(ts))[:19]


def tarjeta(valor, etiqueta, color=None):
    estilo = f' style="color:{color}"' if color else ""
    return (f'<div class="card"><div class="num"{estilo}>{valor}</div>'
            f'<div class="lbl">{e(etiqueta)}</div></div>')


def barras(datos, titulo):
    if not datos:
        return f'<section><h2>{e(titulo)}</h2><p class="vacio">Sin datos</p></section>'
    tope = max(v for _, v, _ in datos) or 1
    alto, filas = 28, []
    for i, (etq, val, col) in enumerate(datos):
        ancho = 60 + int(620 * val / tope)
        y = i * (alto + 10)
        filas.append(
            f'<rect x="150" y="{y}" width="{ancho}" height="{alto}" rx="4" fill="{col}"/>'
            f'<text x="142" y="{y + alto * 0.7}" text-anchor="end" class="etq">{e(etq)}</text>'
            f'<text x="{150 + ancho + 8}" y="{y + alto * 0.7}" class="val">{val}</text>')
    h = len(datos) * (alto + 10)
    return (f'<section><h2>{e(titulo)}</h2>'
            f'<svg viewBox="0 0 820 {h}" width="100%" preserveAspectRatio="xMinYMin meet">'
            f'{"".join(filas)}</svg></section>')


PALETA_TIPO = ["#d95926", "#2a78d6", "#6250d6", "#1baf7a", "#e24b4a", "#eda100", "#8b93a3"]


def distribucion_tipo(registros):
    """Gráfico circular (donut) de la distribución por tipo de evento + leyenda."""
    cuenta = Counter(r.get("tipo", "sin_tipo") for r in registros)
    total = sum(cuenta.values())
    if not total:
        return '<section><h2>Distribución por tipo</h2><p class="vacio">Sin datos</p></section>'
    datos = cuenta.most_common()
    r = 70.0
    circ = 2 * 3.14159265 * r
    segmentos, leyenda, acc = [], [], 0.0
    for i, (tipo, n) in enumerate(datos):
        col = PALETA_TIPO[i % len(PALETA_TIPO)]
        frac = n / total
        dash = frac * circ
        segmentos.append(
            f'<circle cx="90" cy="90" r="{r}" fill="none" stroke="{col}" stroke-width="28" '
            f'stroke-dasharray="{dash:.2f} {circ - dash:.2f}" stroke-dashoffset="{-acc:.2f}"/>')
        acc += dash
        leyenda.append(
            f'<div class="leg"><span class="sw" style="background:{col}"></span>'
            f'{e(tipo)} <b>{n}</b> <span class="pct">({frac * 100:.0f}%)</span></div>')
    donut = (
        '<svg viewBox="0 0 180 180" width="180" height="180" style="transform:rotate(-90deg)">'
        f'{"".join(segmentos)}</svg>')
    centro = (f'<div class="donut-centro"><div class="num">{total}</div>'
              '<div class="lbl">eventos</div></div>')
    return ('<section><h2>Distribución por tipo de evento</h2>'
            f'<div class="donut-wrap"><div class="donut">{donut}{centro}</div>'
            f'<div class="leyenda">{"".join(leyenda)}</div></div></section>')


def _qs():
    return f"?token={TOKEN}" if TOKEN else ""


def explorar(registros):
    if not registros:
        return '<section><h2>Explorar registros</h2><p class="vacio">Sin registros todavía — ' \
               'lanza un ataque y aparecerán aquí.</p></section>'
    tipos = sorted({r.get("tipo", "") for r in registros})
    opciones = '<option value="">Todos los tipos</option>' + "".join(
        f'<option value="{e(t)}">{e(t)}</option>' for t in tipos)
    filas = []
    for i, r in enumerate(reversed(registros), 1):   # los más recientes arriba
        tipo = r.get("tipo", "")
        sev = r.get("severidad", "")
        col = COLOR.get(sev, "#888")
        celda_sev = (f"<span class='pill' style='background:{col}'>{e(sev.upper())}</span>"
                     if sev else "—")
        detalle = e(json.dumps(r, ensure_ascii=False, indent=2))
        filas.append(
            f"<tr data-tipo='{e(tipo)}'>"
            f"<td class='r'>{len(registros) - i + 1}</td><td>{hora(r.get('recibido'))}</td>"
            f"<td>{e(tipo)}</td><td>{e(r.get('metodo', 'POST'))}</td>"
            f"<td>{e(r.get('host', '—'))}</td><td class='mono'>{e(r.get('ip', '—'))}</td>"
            f"<td>{celda_sev}</td><td class='r'>{e(r.get('intentos', '—'))}</td>"
            f"<td class='r'>{e(r.get('fallos', '—'))}</td>"
            f"<td class='mono small'>{e(r.get('id', ''))}</td>"
            f"<td><details><summary>ver</summary><pre class='json'>{detalle}</pre></details></td>"
            f"</tr>")
    return (
        '<section><h2>Explorar registros</h2>'
        '<div class="filtro"><label for="ftipo">Filtrar por tipo</label>'
        f'<select id="ftipo" onchange="filtra()">{opciones}</select>'
        f'<span id="cont" class="cont"></span>'
        f'<a class="btn" href="/datos.csv{_qs()}" download>Descargar CSV</a>'
        f'<a class="btn" href="/datos.json{_qs()}" download>Descargar JSON</a></div>'
        '<div class="tabla-wrap"><table id="tabla-reg">'
        '<thead><tr><th>N.º</th><th>Fecha</th><th>Tipo de evento</th><th>Método HTTP</th>'
        '<th>Host</th><th>IP</th><th>Severidad</th><th>Intentos</th><th>Fallos</th>'
        '<th>ID del registro</th><th>Detalle</th></tr></thead>'
        f'<tbody>{"".join(filas)}</tbody></table></div></section>')


def csv_registros():
    cols = ["N.º", "Fecha", "Tipo de evento", "Método HTTP", "Host", "IP",
            "Severidad", "Intentos", "Fallos", "ID del registro"]

    def esc(v):
        s = "" if v is None else str(v)
        return '"' + s.replace('"', '""') + '"' if any(c in s for c in ',"\n') else s

    with LOCK:
        regs = list(REGISTROS)
    lineas = [",".join(cols)]
    for i, r in enumerate(regs, 1):
        fila = [i, hora(r.get("recibido")), r.get("tipo", ""), r.get("metodo", "POST"),
                r.get("host", ""), r.get("ip", ""), r.get("severidad", ""),
                r.get("intentos", ""), r.get("fallos", ""), r.get("id", "")]
        lineas.append(",".join(esc(v) for v in fila))
    return "\n".join(lineas)


def pagina():
    with LOCK:
        registros = list(REGISTROS)
    alertas = [r for r in registros if r.get("tipo") == "alerta_ssh"]
    por_sev = Counter(a.get("severidad") for a in alertas)
    ips = Counter(a.get("ip") for a in alertas)
    usuarios = Counter(u for a in alertas for u in a.get("usuarios", []))
    cards = "".join([
        tarjeta(len(registros), "Registros"),
        tarjeta(len(alertas), "Alertas"),
        tarjeta(por_sev.get("media", 0), "Media", COLOR["media"]),
        tarjeta(por_sev.get("alta", 0), "Alta", COLOR["alta"]),
        tarjeta(por_sev.get("critica", 0), "Crítica", COLOR["critica"]),
        tarjeta(len(ips), "IPs distintas"),
    ])
    sev_barras = [(s.capitalize(), por_sev.get(s, 0), COLOR[s]) for s in SEV if por_sev.get(s)]
    ip_barras = [(ip, n, "#2a78d6") for ip, n in ips.most_common(8)]
    usr_barras = [(u, n, "#1baf7a") for u, n in usuarios.most_common(8)]
    cuerpo = (
        f'<div class="kpis">{cards}</div>'
        f'<div class="grid2">{distribucion_tipo(registros)}'
        f'{barras(sev_barras, "Alertas por severidad")}</div>'
        f'<div class="grid2">{barras(ip_barras, "Top IPs atacantes")}'
        f'{barras(usr_barras, "Top usuarios probados")}</div>'
        f'{explorar(registros)}')
    return PLANTILLA.format(
        generado=e(f"{datetime.now():%H:%M:%S}"),
        total=len(registros),
        criticas=por_sev.get("critica", 0),
        cuerpo=cuerpo,
    )


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass  # sin ruido en consola

    def _autorizado(self):
        # Si hay TOKEN, se exige en la cabecera X-Token o en el parámetro ?token=.
        if not TOKEN:
            return True
        tok = self.headers.get("X-Token", "")
        if not tok:
            tok = (parse_qs(urlparse(self.path).query).get("token") or [""])[0]
        if hmac.compare_digest(tok, TOKEN):
            return True
        self.send_response(401)
        self.send_header("Content-Length", "0")
        self.end_headers()
        return False

    def do_GET(self):
        if not self._autorizado():
            return
        if self.path.startswith("/datos.csv"):
            self._responde(csv_registros().encode("utf-8-sig"), "text/csv; charset=utf-8")
            return
        if self.path.startswith("/datos"):
            with LOCK:
                cuerpo = json.dumps(REGISTROS, ensure_ascii=False, indent=2).encode()
            self._responde(cuerpo, "application/json")
            return
        self._responde(pagina().encode(), "text/html; charset=utf-8")

    def do_POST(self):
        if not self._autorizado():
            return
        largo = int(self.headers.get("Content-Length", 0) or 0)
        if largo > MAX_BODY:
            self.send_response(413)      # Payload Too Large
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        crudo = self.rfile.read(largo) if largo else b""
        try:
            payload = json.loads(crudo.decode("utf-8", "replace"))
            if not isinstance(payload, dict):
                payload = {"tipo": "desconocido", "crudo": str(payload)}
        except ValueError:
            payload = {"tipo": "no_json", "crudo": crudo.decode("utf-8", "replace")[:500]}
        reg = {
            "id": secrets.token_urlsafe(16),
            "recibido": f"{datetime.now(timezone.utc):%Y-%m-%dT%H:%M:%SZ}",
            "metodo": self.command,
            "remoto": self.client_address[0],
            **payload,
        }
        registra(reg)
        self._responde(b'{"ok":true}', "application/json")

    def _responde(self, cuerpo, tipo):
        self.send_response(200)
        self.send_header("Content-Type", tipo)
        self.send_header("Content-Length", str(len(cuerpo)))
        self.end_headers()
        self.wfile.write(cuerpo)


PLANTILLA = """<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="5">
<title>vigía-ssh · receptor</title>
<style>
  :root {{ color-scheme: dark;
    --bg:#0b0d11; --surf:#13161c; --surf2:#171b22; --bd:#232936; --bd2:#2e3545;
    --tx:#e7eaf0; --mut:#8b93a3; --dim:#5b6373;
    --sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
    --mono:ui-monospace,"JetBrains Mono",Menlo,Consolas,monospace; }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--tx); font-family:var(--sans);
    -webkit-font-smoothing:antialiased; }}
  .barra {{ position:sticky; top:0; z-index:5; background:rgba(11,13,17,.9);
    backdrop-filter:blur(6px); border-bottom:1px solid var(--bd);
    display:flex; align-items:center; gap:14px; padding:16px 28px; flex-wrap:wrap; }}
  .brand {{ font-size:17px; font-weight:500; letter-spacing:.3px; display:flex; align-items:center; gap:9px; }}
  .brand .logo {{ width:22px; height:22px; color:#e24b4a; }}
  .brand b {{ color:#e24b4a; font-weight:500; }}
  .vivo {{ display:flex; align-items:center; gap:7px; font-size:12px; color:#1baf7a;
    background:rgba(27,175,122,.12); border:1px solid rgba(27,175,122,.3);
    padding:4px 10px; border-radius:20px; }}
  .vivo .dot {{ width:7px; height:7px; border-radius:50%; background:#1baf7a;
    box-shadow:0 0 0 0 rgba(27,175,122,.6); animation:pulso 2s infinite; }}
  @keyframes pulso {{ 0%{{box-shadow:0 0 0 0 rgba(27,175,122,.5)}}
    70%{{box-shadow:0 0 0 7px rgba(27,175,122,0)}} 100%{{box-shadow:0 0 0 0 rgba(27,175,122,0)}} }}
  .barra .sep {{ flex:1; }}
  .chip {{ font-size:12px; color:var(--mut); background:var(--surf2); border:1px solid var(--bd);
    padding:4px 11px; border-radius:20px; }}
  .chip b {{ color:var(--tx); font-weight:500; }}
  .chip.cri b {{ color:#e24b4a; }}
  main {{ padding:26px 28px 40px; max-width:1120px; margin:0 auto; }}
  .kpis {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
    gap:14px; margin-bottom:24px; }}
  .card {{ background:var(--surf); border:1px solid var(--bd); border-radius:12px; padding:18px 20px; }}
  .card .num {{ font-size:32px; font-weight:500; font-variant-numeric:tabular-nums; line-height:1; }}
  .card .lbl {{ color:var(--mut); font-size:12px; margin-top:8px; }}
  .grid2 {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(340px,1fr));
    gap:18px; margin-bottom:18px; }}
  .grid2 section {{ margin:0; }}
  section {{ background:var(--surf); border:1px solid var(--bd); border-radius:12px;
    padding:20px 22px; margin-bottom:18px; }}
  section h2 {{ margin:0 0 18px; font-size:13px; font-weight:500; color:var(--mut);
    text-transform:uppercase; letter-spacing:.7px; }}
  svg text {{ fill:#c9cedb; font-size:13px; font-family:var(--sans); }}
  svg text.val {{ fill:var(--mut); }}
  svg text.etq {{ font-size:11px; fill:var(--dim); }}
  table {{ width:100%; border-collapse:collapse; font-size:13px; }}
  thead th {{ position:sticky; top:0; background:var(--surf2); color:var(--mut);
    font-weight:500; text-transform:uppercase; font-size:11px; letter-spacing:.5px;
    text-align:left; padding:11px 12px; border-bottom:1px solid var(--bd2); }}
  tbody td {{ padding:10px 12px; border-bottom:1px solid var(--bd); }}
  tbody tr:nth-child(even) {{ background:rgba(255,255,255,.015); }}
  tbody tr:hover {{ background:rgba(55,138,221,.07); }}
  td.r {{ text-align:right; font-variant-numeric:tabular-nums; }}
  td.mono {{ font-family:var(--mono); color:#6fa8ec; }}
  td.small {{ color:var(--dim); font-size:11px; font-family:var(--mono); }}
  .tabla-wrap {{ overflow-x:auto; max-height:560px; overflow-y:auto; border-radius:8px;
    border:1px solid var(--bd); }}
  .pill {{ display:inline-block; padding:3px 11px; border-radius:20px; color:#0b0d11;
    font-weight:500; font-size:11px; text-transform:uppercase; letter-spacing:.4px; }}
  .filtro {{ display:flex; align-items:center; gap:12px; margin-bottom:14px; flex-wrap:wrap; }}
  .filtro label {{ color:var(--mut); font-size:12px; }}
  .filtro select {{ background:var(--bg); color:var(--tx); border:1px solid var(--bd2);
    border-radius:8px; padding:9px 12px; font:inherit; min-width:220px; }}
  .filtro select:focus {{ outline:none; border-color:#378add; }}
  .filtro .cont {{ color:var(--mut); font-size:12px; }}
  .btn {{ color:var(--tx); background:var(--surf2); border:1px solid var(--bd2); border-radius:8px;
    padding:8px 13px; font-size:12px; text-decoration:none; display:inline-flex; gap:6px; }}
  .btn:hover {{ background:#222838; border-color:#3a4257; }}
  .donut-wrap {{ display:flex; align-items:center; gap:34px; flex-wrap:wrap; }}
  .donut {{ position:relative; width:170px; height:170px; flex:none; }}
  .donut svg {{ width:170px; height:170px; }}
  .donut-centro {{ position:absolute; inset:0; display:flex; flex-direction:column;
    align-items:center; justify-content:center; pointer-events:none; }}
  .donut-centro .num {{ font-size:30px; font-weight:500; font-variant-numeric:tabular-nums; }}
  .donut-centro .lbl {{ color:var(--mut); font-size:11px; }}
  .leyenda {{ display:flex; flex-direction:column; gap:12px; }}
  .leg {{ display:flex; align-items:center; gap:9px; font-size:13px; }}
  .leg .sw {{ width:12px; height:12px; border-radius:3px; display:inline-block; flex:none; }}
  .leg b {{ font-weight:500; font-variant-numeric:tabular-nums; }}
  .leg .pct {{ color:var(--mut); }}
  details summary {{ cursor:pointer; color:#6fa8ec; font-size:12px; list-style:none; }}
  details summary::-webkit-details-marker {{ display:none; }}
  pre.json {{ background:var(--bg); border:1px solid var(--bd); border-radius:8px; padding:12px;
    margin:8px 0 0; max-width:520px; overflow:auto; color:#c9cedb; font-size:12px;
    font-family:var(--mono); white-space:pre; }}
  .vacio {{ color:var(--mut); font-size:13px; }}
  footer {{ padding:22px 28px; color:var(--dim); font-size:12px; text-align:center;
    border-top:1px solid var(--bd); }}
</style></head><body>
<div class="barra">
  <span class="brand"><svg class="logo" viewBox="0 0 24 24" fill="none" stroke="currentColor"
    stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7 3v5c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6z"/></svg>vigía<b>-ssh</b> · receptor</span>
  <span class="vivo"><span class="dot"></span>En vivo</span>
  <span class="sep"></span>
  <span class="chip"><b>{total}</b> registros</span>
  <span class="chip cri"><b>{criticas}</b> críticas</span>
  <span class="chip">Actualizado <b>{generado}</b></span>
</div>
<main>
  {cuerpo}
</main>
<footer>Receptor de webhooks de vigía-ssh — se actualiza solo cada 5 segundos</footer>
<script>
function filtra(){{
  var sel=document.getElementById('ftipo'); if(!sel) return;
  var v=sel.value, n=0, rows=document.querySelectorAll('#tabla-reg tbody tr');
  rows.forEach(function(r){{
    var ok=!v||r.getAttribute('data-tipo')===v;
    r.style.display=ok?'':'none'; if(ok) n++;
  }});
  document.getElementById('cont').textContent='Mostrando '+n+' de '+rows.length+' registros';
}}
filtra();
</script>
</body></html>"""


def main():
    global STORE, TOKEN
    p = argparse.ArgumentParser(description="Receptor de webhooks de vigia-ssh con dashboard")
    p.add_argument("-p", "--puerto", type=int, default=8000)
    p.add_argument("--host", default=os.environ.get("VIGIA_RECEPTOR_HOST", "127.0.0.1"),
                   help="interfaz donde escucha (def. 127.0.0.1, solo local; 0.0.0.0 = todas)")
    p.add_argument("--token", default=os.environ.get("VIGIA_RECEPTOR_TOKEN", ""),
                   help="si se indica, exige ?token= o la cabecera X-Token en cada petición")
    p.add_argument("--store", default=STORE, help="fichero donde guarda los registros")
    a = p.parse_args()
    STORE = a.store
    TOKEN = a.token
    if a.host not in ("127.0.0.1", "localhost", "::1") and not TOKEN:
        p.error("exponer el receptor en una interfaz de red (--host %s) exige --token "
                "(o la variable VIGIA_RECEPTOR_TOKEN). Sin token solo se permite 127.0.0.1." % a.host)
    carga()
    srv = ThreadingHTTPServer((a.host, a.puerto), Handler)
    print(f"receptor escuchando en http://{a.host}:{a.puerto}/  ({len(REGISTROS)} registros cargados)")
    print(f"guardando en {STORE} · Ctrl+C para parar")
    if a.host != "127.0.0.1":
        print(f"expuesto en {a.host} con token obligatorio.")
    if TOKEN:
        print("token exigido: usa la cabecera X-Token, o ?token=TU_TOKEN en la URL y en CANAL.")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nparado")


if __name__ == "__main__":
    main()
