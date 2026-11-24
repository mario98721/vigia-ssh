# Seguridad

## Cómo informar de una vulnerabilidad

Si encuentras un fallo de seguridad, no abras un issue público. Usa
**Security → Report a vulnerability** en este repositorio (aviso privado de
GitHub) e incluye versión (`vigia_ssh.py -V`), pasos para reproducirlo y el
impacto.

## Qué es sensible

- La URL del webhook
- `/etc/vigia/lista_blanca.json`: revela qué máquinas no deben alertar.
- `/var/lib/vigia/estado.json`: historial de IPs alertadas y bloqueadas, y
  alertas pendientes de entregar.
- `/var/log/ssh_honeypot.jsonl`: contraseñas probadas contra el honeypot. Pueden
  incluir contraseñas reales de alguien que se equivocó de puerto.

## Buenas prácticas

- `config/vigia.conf.example` se mantiene con `CANAL=` vacío.
- Configuración y lista blanca con permisos `640 root:root`.
- Rota el webhook si sospechas que se ha filtrado; los de Discord y
  `webhook.cool` se regeneran desde su panel.
- Usa `https://` para el webhook; con `http://` el detector avisa al arrancar.

## Decisiones de diseño

- El nombre de usuario de SSH lo controla el atacante y puede contener
  espacios y un `from <IP>` falso. La IP se toma siempre del final de la línea
  del journal, así que nadie puede hacer bloquear a una IP de terceros
  (misma clase de fallo que CVE-2006-6302 en fail2ban).
- Nunca se alertan ni se bloquean el loopback, las IPs del propio equipo ni las
  de la lista blanca.
- El bloqueo no depende del webhook: un canal caído o un mensaje rechazado no
  dejan al atacante sin bloquear.
- En los mensajes de Discord los usuarios se recortan y se limpian, y las
  menciones están desactivadas (`allowed_mentions` vacío). El JSON de la alerta
  sigue el contrato tal cual.
- Sin terminal para confirmar un bloqueo, no se bloquea (fallo seguro).
- El servicio systemd corre con `CapabilityBoundingSet=CAP_NET_ADMIN`,
  `ProtectSystem=strict` y filtro de llamadas al sistema; solo escribe en
  `/var/lib/vigia` y `/var/log/vigia`.
- El honeypot abre el puerto y el log como root y después baja a `nobody`, con
  tope de conexiones y de duración por conexión, y escapa lo que pinta.

## Permisos que espera el instalador

| Ruta | Modo |
| --- | --- |
| `/etc/vigia` | 755 |
| `/etc/vigia/vigia.conf` | 640 |
| `/etc/vigia/lista_blanca.json` | 640 |
| `/var/lib/vigia` | 700 |
| `/var/log/vigia` | 750 |
| `/var/log/ssh_honeypot.jsonl` | 600 |
| `/usr/local/bin/vigia_ssh.py` | 750 |

## Alcance

Herramienta de laboratorio y aprendizaje, pensada para ejecutarse como root en un
servidor de pruebas. El detector (`vigia_ssh.py`) no tiene autenticación propia: se
administra en local por línea de órdenes y confía en los permisos del sistema. El
receptor del dashboard (`dashboard/receptor.py`) sí admite un token (`--token`),
escucha solo en `127.0.0.1` por defecto y exige token para exponerse en red. No
sustituye a fail2ban, a CrowdSec ni a desactivar el acceso por contraseña en SSH.
