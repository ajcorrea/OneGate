#!/bin/bash
# Instala o ONE GATE de laboratório numa VM Ubuntu Server 24.04.
#
#   git clone -b fase1/mvp https://github.com/ajcorrea/OneGate.git
#   cd OneGate/deploy/lab
#   sudo ./instalar-vm.sh --placa-lab ens224
#
# --placa-lab: placa ligada à rede do laboratório (port group do EVE-NG). Recebe 10.99.0.10
#              (Edge e "rede NOC") e 10.99.0.50 ("notebook do técnico"). Sem ela, configure à mão.
# --login:     login do Admin global no painel (padrão: admin).
set -euo pipefail
cd "$(dirname "$0")"

PLACA=""
LOGIN="admin"
while [ $# -gt 0 ]; do
  case "$1" in
    --placa-lab) PLACA="$2"; shift 2 ;;
    --login) LOGIN="$2"; shift 2 ;;
    *) echo "opção desconhecida: $1"; exit 2 ;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "Rode com sudo."; exit 1; }
passo() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }

passo "Pacotes (Docker, Compose, Python)"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq docker.io docker-compose-v2 python3 openssl telnet openssh-client ca-certificates >/dev/null
systemctl enable --now docker >/dev/null

if [ -n "$PLACA" ]; then
  passo "Rede do laboratório na placa $PLACA (10.99.0.10 e 10.99.0.50)"
  ip link show "$PLACA" >/dev/null || { echo "Placa $PLACA não existe (veja: ip -br link)"; exit 1; }
  cat > /etc/netplan/60-onegate-lab.yaml <<EOF
network:
  version: 2
  ethernets:
    $PLACA:
      dhcp4: false
      addresses: [10.99.0.10/24, 10.99.0.50/24]
EOF
  chmod 600 /etc/netplan/60-onegate-lab.yaml
  netplan apply
fi
ip -br addr 2>/dev/null | grep -q '10\.99\.0\.10/' || echo "AVISO: 10.99.0.10 não está configurado; o Edge não vai subir até configurar."

passo "Segredos (.env)"
if [ ! -f .env ]; then
  umask 077
  cat > .env <<EOF
# Gerado por instalar-vm.sh. Guarde uma cópia: sem ONEGATE_SECRET_KEY os segredos cifrados ficam ilegíveis.
DB_PASSWORD=$(openssl rand -hex 16)
ONEGATE_SECRET_KEY=$(openssl rand -base64 32)
EDGE_PUBKEY=pendente
EDGE_LISTEN=10.99.0.10:49
PAINEL_PORTA=8080
EOF
  echo "Criado deploy/lab/.env"
else
  echo ".env já existe: mantido."
fi
mkdir -p dados/politicas dados/edge
chown 65532:65532 dados/politicas && chmod 700 dados/politicas

passo "Build das imagens e subida do banco e do painel (alguns minutos na primeira vez)"
docker compose build
docker compose up -d db api
for i in $(seq 1 60); do
  curl -fs "http://127.0.0.1:$(grep ^PAINEL_PORTA .env | cut -d= -f2)/api/health" >/dev/null 2>&1 && break
  sleep 2
done
curl -fs "http://127.0.0.1:$(grep ^PAINEL_PORTA .env | cut -d= -f2)/api/health" >/dev/null || { docker compose logs api | tail -20; exit 1; }

passo "Chave pública das políticas (assinatura Ed25519)"
PUB=$(docker compose exec -T api /usr/local/bin/onegate-api policy-pubkey 2>/dev/null | tr -d '\r')
sed -i "s|^EDGE_PUBKEY=.*|EDGE_PUBKEY=$PUB|" .env
echo "EDGE_PUBKEY=$PUB"

if [ -f credenciais-lab.txt ]; then
  echo "credenciais-lab.txt já existe: o laboratório já foi populado. Pulando admin e dados de exemplo."
else
  passo "Admin global e dados de exemplo"
  SENHA="Admin-$(openssl rand -base64 12 | tr -d '/+=')"
  printf '%s\n' "$SENHA" | docker compose exec -T api /usr/local/bin/onegate-api bootstrap-admin \
    --login "$LOGIN" --name "Admin do laboratório" >/dev/null
  python3 popular-lab.py --url "http://127.0.0.1:$(grep ^PAINEL_PORTA .env | cut -d= -f2)" \
    --painel-url "http://$(hostname -I | awk '{print $1}'):$(grep ^PAINEL_PORTA .env | cut -d= -f2)" \
    --login "$LOGIN@onegate.systems" --senha "$SENHA"
  sed -i "3a Senha do painel: $SENHA" credenciais-lab.txt
fi

passo "Política assinada → Edge"
./publicar-politica.sh LAB

IP=$(hostname -I | awk '{print $1}')
cat <<EOF

Pronto.
  Painel:       http://$IP:$(grep ^PAINEL_PORTA .env | cut -d= -f2)
  Credenciais:  $(pwd)/credenciais-lab.txt   (sudo cat credenciais-lab.txt)
  Edge:         TACACS+ em $(grep ^EDGE_LISTEN .env | cut -d= -f2) · eventos em $(pwd)/dados/edge/events.jsonl
  Roteiro:      $(pwd)/TESTES.md

Depois de mudar regras no painel e publicar, rode: sudo ./publicar-politica.sh
Aguarde 30 s antes do primeiro login no painel (o código TOTP atual já foi usado pelo instalador).
EOF
