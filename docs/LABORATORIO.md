# Montaje del laboratorio

Dos máquinas en red NAT de VirtualBox, red `red-lab` 10.0.2.0/24 con DHCP
desactivado.

| Rol | IP |
| --- | --- |
| Atacante | 10.0.2.24 |
| Víctima / monitor | 10.0.2.20 |
| Puerta de enlace | 10.0.2.1 |
| DNS | 10.0.2.3 |

## Víctima

~~~bash
sudo apt install -y openssh-server
sudo systemctl enable --now ssh
sudo sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
sudo sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
sudo sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 100/' /etc/ssh/sshd_config
sudo sed -i '/^#*PerSourcePenalties/d' /etc/ssh/sshd_config
echo 'PerSourcePenalties no' | sudo tee -a /etc/ssh/sshd_config
sudo sshd -t && sudo systemctl restart ssh
~~~

Estos ajustes (root por contraseña, 100 intentos, sin penalizaciones) son solo para el
laboratorio: en una máquina real déjalos como venían.

`PerSourcePenalties no` es clave: con OpenSSH 9.8+ sshd penaliza la IP tras
varios fallos y suelta las conexiones nuevas (`Connection reset by peer`), lo
que rompe cualquier prueba con hydra.

## Atacante

~~~bash
sudo apt install -y hydra sshpass
~~~

## Verificación

~~~bash
nc -vz 10.0.2.20 22
sshpass -p TU_PASSWORD ssh -o StrictHostKeyChecking=no kali@10.0.2.20 'echo ok'
~~~
