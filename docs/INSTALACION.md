# Instalación

## Requisitos

- Linux con systemd, Python 3.10+
- `nftables` (o `iptables`), `openssh-server`
- `python3-paramiko` solo si vas a usar el honeypot
- `jq` solo para `vigia_genera_muestra.sh`

~~~bash
sudo apt update
sudo apt install -y nftables python3-paramiko jq
~~~

## Instalación

~~~bash
git clone https://github.com/mario98721/vigia-ssh.git
cd vigia-ssh
sudo ./install.sh
~~~

Después:

1. `sudo nano /etc/vigia/vigia.conf` y pon tu `CANAL`.
2. `sudo nano /etc/vigia/lista_blanca.json` con tus IPs o redes de administración.
3. `sudo vigia_ssh.py -t` debe acabar en `AUTOTEST OK`.
4. `sudo vigia_ssh.py --demo` para la demostración completa.
5. `sudo systemctl enable --now vigia-ssh` para dejarlo como servicio.

## Rutas

| Qué | Dónde |
| --- | --- |
| Binarios | `/usr/local/bin/vigia_ssh.py`, `honeypot.py`, `ver_ataques.sh`, `ver_intentos.sh`, `ver_alertas.sh` |
| Configuración | `/etc/vigia/vigia.conf` |
| Lista blanca | `/etc/vigia/lista_blanca.json` |
| Estado antiduplicados | `/var/lib/vigia/estado.json` |
| Histórico de alertas | `/var/log/vigia/alertas.log` |
| Log del honeypot | `/var/log/ssh_honeypot.jsonl` (permisos 600) |

## Desinstalar

~~~bash
sudo ./uninstall.sh
~~~
