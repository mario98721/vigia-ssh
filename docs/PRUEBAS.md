# Pruebas y evidencias

## Unitarias

~~~bash
python3 -m unittest discover -s tests -v
~~~

Sin root ni red. Incluyen los casos de seguridad: usuarios con `from <IP>`
inyectado, loopback, webhook caído, ráfaga seguida de silencio y honeypot.

## Autotest y demo

~~~bash
sudo vigia_ssh.py -t
sudo vigia_ssh.py --demo
~~~

## Ataque real

Víctima, terminal 1 (si el servicio está en marcha, páralo antes con
`sudo systemctl stop vigia-ssh`: solo puede correr una instancia):

~~~bash
sudo vigia_ssh.py -R
sudo vigia_ssh.py -C -e 60
~~~

Víctima, terminal 2:

~~~bash
sudo ver_alertas.sh -f
~~~

Atacante:

~~~bash
vigia_simula_ataque.sh 10.0.2.20 100 22
~~~

## Criterios de aceptación

- Una única alerta por IP y ráfaga, con `severidad` alta.
- Repetición dentro del enfriamiento: cero alertas, aviso `Omite alerta duplicada`.
- Acceso correcto tras los fallos: `severidad` critica.
- La IP de la víctima y las de la lista blanca nunca aparecen alertadas.
- Un usuario con `from <otra IP>` dentro alerta y bloquea la IP real del
  atacante, nunca la inventada. Desde el atacante:

  ~~~bash
  for i in $(seq 12); do
    sshpass -p x ssh -o StrictHostKeyChecking=no -o PubkeyAuthentication=no \
      -l 'x from 10.0.2.99' 10.0.2.20 true
  done
  ~~~
- Con `-B`, `nft list table inet vigia` muestra la IP y el ping del atacante cae.

## Honeypot (opcional)

Solo para ver las contraseñas, en el 2222. El honeypot no las pinta en su
salida; las enseña `ver_ataques.sh`, leyendo el log con permisos 600:

~~~bash
sudo python3 /usr/local/bin/honeypot.py 2222 &
sudo ver_ataques.sh -f
vigia_simula_ataque.sh 10.0.2.20 50 2222   # desde el atacante
~~~
