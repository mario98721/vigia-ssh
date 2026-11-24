# Configuración

Todo va en `/etc/vigia/vigia.conf`. Los valores de la línea de órdenes
sobrescriben el fichero. Tras editarlo, comprueba con `sudo vigia_ssh.py -t`.

## Claves

| Clave | Valor por defecto | Qué hace | Cuándo cambiarla |
| --- | --- | --- | --- |
| `UMBRAL` | 5 | Fallos por IP antes de alertar | Bájalo en aulas ruidosas, súbelo si hay mucho escaneo |
| `VENTANA_MIN` | 5 | Minutos que se miran hacia atrás | Súbelo para ataques lentos |
| `ENFRIAMIENTO` | 600 | Segundos de silencio por IP tras alertar | Bájalo en demos, súbelo en producción |
| `RESUMEN_MIN` | 5 | Minutos entre resúmenes, 0 lo desactiva | 0 si no quieres resúmenes |
| `DESBLOQUEO_MIN` | 0 (30 en el ejemplo) | Minutos hasta que caduca un bloqueo, 0 nunca | Súbelo si los bloqueos deben durar |
| `BLOQUEO_MIN_SEV` | alta | Severidad mínima para bloquear | `media` bloquea antes, `critica` solo accesos |
| `THROTTLE` | 10 | Segundos entre análisis en modo continuo | Bájalo para reaccionar antes |
| `UNIDADES` | `ssh sshd` | Unidades de systemd que se leen | Si tu `sshd` corre con otro nombre de unidad |
| `CANAL` | vacío | URL del webhook | Obligatorio salvo en `-n` |

## Poner el webhook

Discord: canal, Editar canal, Integraciones, Webhooks, Nuevo, copiar URL.

Después:

    sudo sed -i 's#^CANAL=.*#CANAL=https://discord.com/api/webhooks/XXXX/YYYY#' /etc/vigia/vigia.conf
    sudo grep CANAL /etc/vigia/vigia.conf

## Lista blanca

Un array JSON de IPs o redes CIDR, IPv4 o IPv6. Formato exacto:

    ["10.0.2.1", "10.0.2.20", "192.168.56.0/24", "2001:db8::/32"]

Las entradas que no son una IP o una red válida se ignoran y quedan anotadas en
`/var/log/vigia/alertas.log`.

Pon la puerta de enlace y las IPs desde las que administras. Las IPs del propio
equipo y el loopback se añaden solas, pero ponerlas no estorba.

## Permisos

    sudo chown root:root /etc/vigia/vigia.conf /etc/vigia/lista_blanca.json
    sudo chmod 640 /etc/vigia/vigia.conf /etc/vigia/lista_blanca.json

El webhook es un secreto: déjalo en el fichero. Pasado con `-c`, cualquier
usuario del equipo lo ve con `ps`.

## Verificar

    sudo vigia_ssh.py -t
    sudo vigia_ssh.py -E
