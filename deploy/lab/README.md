# Laboratório ONE GATE no EVE-NG (VMware)

Ambiente isolado para testar o ONE GATE com equipamentos virtuais, sem tocar na produção.

```
VMware ESXi
├── VM "onegate-lab" (Ubuntu Server 24.04)
│     placa 1: rede da empresa  → painel em http://<ip>:8080
│     placa 2: port group ONEGATE-LAB → 10.99.0.10 (Edge e "rede NOC")
│                                     10.99.0.50 ("notebook do técnico")
│     containers: PostgreSQL · API + painel · Edge (TACACS+ na porta 49)
│
└── VM "eve-ng"
      placa 1: rede da empresa  → interface web do EVE
      placa 2: port group ONEGATE-LAB → Cloud1 dentro do EVE
      laboratório:
        Cloud1 (10.99.0.0/24)
         ├── Arista vEOS-lab   10.99.0.2   grupo Acesso (MFA desligado)   ← gratuito, testa agora
         ├── MikroTik CHR      10.99.0.4   grupo Borda                    ← gratuito, só RADIUS (dia 8)
         ├── Huawei NE40E      10.99.0.1   grupo Núcleo (MFA TOTP)        ← quando houver imagem
         └── Cisco IOSv/IOL    10.99.0.3   grupo Borda                    ← quando houver imagem
```

A VM do ONE GATE fica fora do EVE de propósito: sem virtualização aninhada, ela fica leve e
estável, e o "técnico" pode testar direto dela (com os dois IPs de origem).

## 1. VMware: rede do laboratório

1. Crie um **vSwitch sem uplink** (ou use um existente) e nele o port group **ONEGATE-LAB**.
2. Em **Segurança** do port group, deixe **Aceitar** em: Modo promíscuo, Alterações de endereço MAC
   e Transmissões forjadas. Sem isso, o EVE não consegue ligar os equipamentos virtuais à rede.

## 2. VM do ONE GATE

- Ubuntu Server 24.04 · 2 vCPU · 4 GB de RAM · 40 GB de disco
- Placa 1 na rede da empresa (com internet para baixar pacotes e imagens)
- Placa 2 no port group ONEGATE-LAB, **sem IP** (o instalador configura)

```bash
sudo apt-get install -y git
git clone -b fase1/mvp https://github.com/ajcorrea/OneGate.git
cd OneGate/deploy/lab
ip -br link                                   # descubra o nome da placa 2 (ex.: ens224)
sudo ./instalar-vm.sh --placa-lab ens224      # 5 a 10 minutos na primeira vez
sudo cat credenciais-lab.txt                  # senhas e TOTPs do laboratório
```

O instalador:
- instala o Docker e configura 10.99.0.10 e 10.99.0.50 na placa 2;
- gera as senhas e a chave mestra em `.env` (**guarde uma cópia**);
- sobe banco, API e painel, e cria o Admin global;
- popula o cliente **LAB** (`@lab.ontelecom.io`) com técnicos, objetos, equipamentos e regras, e publica;
- gera a política assinada e liga o Edge.

Abra o painel, entre como `admin@onegate.systems` e cadastre o TOTP do painel no app autenticador
(o segredo também está em `credenciais-lab.txt`). Cadastre ainda os TOTPs dos técnicos `noc.lab`,
`suporte.n1` e `terceiro`.

**Sempre que publicar regras ou mudar equipamentos/técnicos no painel:**
`sudo ./publicar-politica.sh` (até o canal seguro com o Edge ficar pronto, no dia 3).

## 3. VM do EVE-NG

- **Processador Intel** (o EVE não suporta AMD dentro do ESXi)
- 8 vCPU · 16 a 32 GB de RAM · 150 GB de disco
- Em CPU: marque **Expor virtualização assistida por hardware ao sistema operacional convidado**
- Placa 1 na rede da empresa; placa 2 no port group ONEGATE-LAB
- Instale o EVE-NG Community pela ISO oficial (eve-ng.net → Download → Community)

No EVE, a placa 2 vira **pnet1**, que aparece nos laboratórios como a rede **Cloud1**.

## 4. Imagens gratuitas

Pelo SSH do EVE, como root. Depois de copiar cada imagem: `/opt/unetlab/wrappers/unl_wrapper -a fixpermissions`.

**Arista vEOS-lab** (cadastro gratuito em arista.com → Support → Software Download → vEOS-lab):
```bash
mkdir -p /opt/unetlab/addons/qemu/veos-4.32.0F          # use a versão baixada
cd /opt/unetlab/addons/qemu/veos-4.32.0F
# se baixou .vmdk:  /opt/qemu/bin/qemu-img convert -f vmdk -O qcow2 vEOS-lab-4.32.0F.vmdk hda.qcow2
# se baixou .qcow2: mv vEOS-lab-4.32.0F.qcow2 hda.qcow2
# se o pacote trouxer Aboot-veos-*.iso: mv Aboot-veos-*.iso cdrom.iso
```

**MikroTik CHR** (mikrotik.com → Software → Cloud Hosted Router → "Raw disk image"):
```bash
mkdir -p /opt/unetlab/addons/qemu/mikrotik-7.16
cd /opt/unetlab/addons/qemu/mikrotik-7.16
unzip chr-7.16.img.zip && /opt/qemu/bin/qemu-img convert -f raw -O qcow2 chr-7.16.img hda.qcow2 && rm chr-7.16.img
```

**Huawei NE40E e Cisco** dependem de conta nos fabricantes (portal Huawei com a conta de suporte;
Cisco Modeling Labs). As configurações já estão prontas em `configs/`.

## 5. Montar o laboratório no EVE

1. Novo laboratório "ONE GATE AAA".
2. **Add Network** → tipo **Cloud1**.
3. **Add Node**: Arista vEOS (2 vCPU, 2 GB) e, se quiser, MikroTik CHR (1 vCPU, 256 MB).
4. Ligue a **primeira interface** de cada nó à Cloud1 (no Arista é a Management1; no MikroTik, ether1).
5. Inicie os nós, abra o console e cole o arquivo de `configs/` correspondente.
6. Teste da VM do ONE GATE: `ping 10.99.0.2`.

Siga o roteiro em [TESTES.md](TESTES.md).

## Comandos úteis (na pasta deploy/lab)

| O quê | Comando |
|---|---|
| Ver os logins e comandos ao vivo | `sudo tail -f dados/edge/events.jsonl` |
| Logs do Edge / da API | `sudo docker compose logs -f edge` · `... api` |
| Simular o Edge fora do ar | `sudo docker compose stop edge` (volta com `start edge`) |
| Atualizar o código | `git pull && sudo docker compose build && sudo docker compose --profile edge up -d` |
| Recomeçar do zero | `sudo docker compose --profile edge down -v && sudo rm -rf dados .env credenciais-lab.txt` |
