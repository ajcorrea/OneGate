#!/bin/sh
# Gera o pacote assinado do cliente com as regras publicadas no painel e entrega ao Edge.
# Uso: ./publicar-politica.sh [CODIGO_DO_CLIENTE]   (padrão: LAB)
# Até o canal seguro (dia 3 do cronograma), este é o caminho nuvem → Edge.
set -eu
cd "$(dirname "$0")"
CLIENTE="${1:-LAB}"
docker compose exec -T api /usr/local/bin/onegate-api export-policy --customer "$CLIENTE" --out /politicas/policy.json
if [ -n "$(docker compose ps -q --status running edge 2>/dev/null)" ]; then
  docker compose kill -s HUP edge >/dev/null
  echo "Edge recarregado."
else
  docker compose --profile edge up -d edge
  echo "Edge iniciado."
fi
sleep 1
docker compose logs --tail 4 edge
