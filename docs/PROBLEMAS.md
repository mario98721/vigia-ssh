# Problemas frecuentes

| Síntoma | Causa | Arreglo |
| --- | --- | --- |
| `command not found` con sudo | `/usr/local/bin` fuera del PATH de sudo | `install.sh` ya crea los enlaces en `/usr/bin`; vuelve a ejecutarlo |
| `journalctl` devuelve vacío | Falta root o grupo `systemd-journal` | Ejecuta con `sudo` |
| No hay eventos al atacar | Unidad con otro nombre | `systemctl status ssh sshd` y ajusta `UNIDADES` |
| `Connection reset by peer` con hydra | `PerSourcePenalties` de OpenSSH 9.8+ | Ver `docs/LABORATORIO.md` |
| `maximum authentication attempts exceeded` | `MaxAuthTries` bajo | `MaxAuthTries 100` y reiniciar sshd |
| Alerta duplicada | Enfriamiento demasiado corto | `-e 600` y revisa `estado.json` |
| El bloqueo no corta al atacante | Regla no aplicada o caducada | `sudo nft list table inet vigia` |
| `NO se pudo bloquear` | nftables falló o no hay cortafuegos | El motivo exacto está en `/var/log/vigia/alertas.log` |
| `sin terminal para confirmar` | `-B` sin `-s` desde cron o un servicio | Añade `-s` si quieres bloqueo sin preguntar |
| El servicio se para tras varios reinicios | Falta `CANAL` u otro error de configuración | `journalctl -u vigia-ssh -n 20`, corrige y `systemctl reset-failed vigia-ssh` |
| Alertas en cola sin entregar | Webhook caído o URL caducada | `sudo vigia_ssh.py -E` muestra `pendientes`; se reintentan cada minuto |
| Me he bloqueado a mí mismo | IP fuera de la lista blanca | Consola de la VM y `sudo nft delete table inet vigia` |
| `Address already in use` | Otro proceso en el puerto | `sudo ss -ltnp` y matar por PID |
| Webhook devuelve 404 | El bin caducó | Crear otro y actualizar `CANAL` |
| `No queda espacio` | Disco lleno | `journalctl --vacuum-size=100M` y `apt clean` |

## Diagnóstico general

    sudo vigia_ssh.py -V
    sudo vigia_ssh.py -t
    sudo journalctl -u ssh -u sshd -n 20
    sudo ss -ltnp | grep ':22'
    sudo nft list ruleset
    sudo tail -20 /var/log/vigia/alertas.log
