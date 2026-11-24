#!/usr/bin/env bash
# install.sh — instalación del detector en el sistema local.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "ejecuta con sudo"; exit 1; }
SRC=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
for dep in python3 journalctl; do
  command -v "$dep" >/dev/null || { echo "falta $dep"; exit 1; }
done
command -v nft >/dev/null || echo "aviso: sin nftables el bloqueo usará iptables (o no bloqueará)"

install -d -m 755 /etc/vigia /usr/local/bin
install -d -m 700 /var/lib/vigia
install -d -m 750 /var/log/vigia

install -m 750 "$SRC/bin/vigia_ssh.py" /usr/local/bin/vigia_ssh.py
install -m 750 "$SRC/bin/honeypot.py" /usr/local/bin/honeypot.py
install -m 750 "$SRC/bin/ver_ataques.sh" /usr/local/bin/ver_ataques.sh
install -m 750 "$SRC/bin/ver_intentos.sh" /usr/local/bin/ver_intentos.sh
install -m 750 "$SRC/bin/ver_alertas.sh" /usr/local/bin/ver_alertas.sh
install -m 750 "$SRC/tools/genera_muestra.sh" /usr/local/bin/vigia_genera_muestra.sh
install -m 750 "$SRC/tools/simula_ataque.sh" /usr/local/bin/vigia_simula_ataque.sh
# Kali y otras distros dejan /usr/local/bin fuera del secure_path de sudo: sin estos
# enlaces, "sudo ver_alertas.sh" da "command not found". Nunca se pisa un fichero real.
for b in vigia_ssh.py honeypot.py ver_ataques.sh ver_intentos.sh ver_alertas.sh; do
  [[ -e /usr/bin/$b && ! -L /usr/bin/$b ]] || ln -sf "/usr/local/bin/$b" "/usr/bin/$b"
done

[[ -f /etc/vigia/vigia.conf ]] || install -m 640 "$SRC/config/vigia.conf.example" /etc/vigia/vigia.conf
[[ -f /etc/vigia/lista_blanca.json ]] || install -m 640 "$SRC/config/lista_blanca.json.example" /etc/vigia/lista_blanca.json

install -m 644 "$SRC/systemd/vigia-ssh.service" /etc/systemd/system/vigia-ssh.service
systemctl daemon-reload
# Si el servicio ya estaba en marcha, que use el código recién instalado.
systemctl try-restart vigia-ssh 2>/dev/null || true

cat <<'EOF'
Instalado. Siguiente:

  1. Edita /etc/vigia/vigia.conf y pon CANAL=<tu webhook>
  2. Revisa /etc/vigia/lista_blanca.json (tus IPs de administración)
  3. Prueba:  sudo vigia_ssh.py -t
  4. Demo:    sudo vigia_ssh.py --demo
  5. Servicio: sudo systemctl enable --now vigia-ssh
EOF
