# Conceptos

Para quien llega sin contexto. Se lee una vez y ya se entiende el resto.

## journalctl y el formato JSON

`sshd` escribe cada intento de acceso en el journal del sistema. `journalctl`
es la herramienta para leerlo. Con `-o json` devuelve un objeto JSON por línea
(JSON Lines), con campos como `MESSAGE` y `__REALTIME_TIMESTAMP`.

El detector no usa el texto libre: parsea ese JSON, se queda con `MESSAGE` y
extrae de ahí usuario e IP con una expresión regular. Lee las unidades `ssh`
(Debian, Ubuntu, Kali) y `sshd` (RHEL, Fedora, Arch); se cambia con `UNIDADES`.

## Qué cuenta como intento

- Fallo: `Failed password …` y, si el servidor usa keyboard-interactive con
  PAM, `error: PAM: Authentication failure …` (una línea por intento).
- Acceso: `Accepted password …` y `Accepted keyboard-interactive/pam …`.

Todo lo demás se ignora (desconexiones, claves públicas, escaneos de banner).

## Por qué la IP se lee del final de la línea

El nombre de usuario lo elige el cliente y `sshd` lo registra tal cual, con
espacios. Si alguien se conecta con el usuario `x from 10.0.2.50`, el journal
dice:

    Failed password for invalid user x from 10.0.2.50 from 10.0.2.24 port 4242 ssh2

La IP buena es la última, la que escribe `sshd` justo antes de `port`. Un
parser que se quede con la primera IP que vea bloquearía a 10.0.2.50, una
máquina inocente. Por eso la expresión regular va anclada al final de la línea.

## Severidad

- `media`: la IP alcanza el umbral de fallos.
- `alta`: lo duplica.
- `critica`: la IP consigue un acceso después de haber fallado, señal de que ha
  adivinado la contraseña. Un acceso anterior a los fallos no cuenta.

## Umbral y ventana

El umbral (`-u`) es el número de fallos a partir del cual una IP alerta. La
ventana (`-w`) es cuántos minutos atrás se miran. Por defecto 5 fallos en 5
minutos. Una IP con 4 fallos en la ventana no alerta.

## Enfriamiento

Tras alertar de una IP, el detector la silencia durante un tiempo (`-e`, 600
segundos por defecto) para no inundar el canal. Si vuelve a atacar pasado ese
tiempo, alerta de nuevo. Conviene que el enfriamiento no sea menor que la
ventana; si lo es, el detector avisa al arrancar.

## Lista blanca e IPs locales

`/etc/vigia/lista_blanca.json` contiene IPs o redes CIDR que nunca generan
alerta ni se bloquean: la puerta de enlace, tu equipo de administración, la red
de gestión. Además, el detector añade solas todas las IPs del propio equipo
(IPv4 e IPv6) y el loopback, así que la máquina nunca se bloquea a sí misma.

## Bloqueo con nftables

`nftables` es el cortafuegos del kernel. Con `-B`, el detector añade la IP a un
conjunto (`bloqueadas` para IPv4, `bloqueadas6` para IPv6) de la tabla
`inet vigia`, cuyas IPs se descartan en la entrada. Con `-d`, cada IP caduca
sola a los minutos indicados.

Si no hay nftables, usa `iptables` o `ip6tables`. En ese caso la caducidad la
aplica el propio detector, y solo cuando corre en modo continuo.

El bloqueo no espera al webhook: si el canal está caído, la IP se bloquea igual
y la alerta queda en cola para reintentarla.

## Webhook

Una URL a la que se hace `POST` con el JSON de la alerta: Discord, un bin de
`webhook.cool` o un receptor propio. Es un secreto: quien la tenga puede
publicar en el canal. Mejor en el fichero de configuración que en `-c`, porque
la línea de órdenes la ve cualquier usuario con `ps`.

## Ensayo (`-n`)

Imprime lo que alertaría y no envía, no bloquea ni toca el estado real. Se
puede lanzar aunque el servicio esté en marcha.

## Un solo proceso

El script toma un cerrojo (`flock`). Si lanzas dos, el segundo sale con
`ya hay una instancia en marcha`. Evita alertas duplicadas.
