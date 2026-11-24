#!/usr/bin/env bash
# uninstall.sh — desinstalación completa.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "ejecuta con sudo"; exit 1; }
systemctl disable --now vigia-ssh 2>/dev/null || true
rm -f /etc/systemd/system/vigia-ssh.service
systemctl daemon-reload
nft delete table inet vigia 2>/dev/null || true
rm -f /usr/local/bin/vigia_ssh.py /usr/local/bin/honeypot.py \
      /usr/local/bin/ver_ataques.sh /usr/local/bin/ver_intentos.sh /usr/local/bin/ver_alertas.sh \
      /usr/local/bin/vigia_genera_muestra.sh /usr/local/bin/vigia_simula_ataque.sh
for b in vigia_ssh.py honeypot.py ver_ataques.sh ver_intentos.sh ver_alertas.sh; do
  if [[ $(readlink "/usr/bin/$b" 2>/dev/null) == "/usr/local/bin/$b" ]]; then rm -f "/usr/bin/$b"; fi
done
rm -rf /var/lib/vigia /var/log/vigia /var/log/ssh_honeypot.jsonl
echo "desinstalado. /etc/vigia se conserva; bórralo a mano si quieres."
