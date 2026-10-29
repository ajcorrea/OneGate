# ONE GATE — laboratório: MikroTik CHR (ether1 ligado à Cloud1 do EVE)
# ATENÇÃO: o RouterOS não fala TACACS+, só RADIUS. Este equipamento entra nos testes
# quando o RADIUS do Edge ficar pronto (dia 8 do cronograma). Até lá ele só pinga.
/system identity set name=lab-mikrotik
/ip address add address=10.99.0.4/24 interface=ether1
/user add name=emergencia group=full password=OneGate-Emergencia-2026
/radius add service=login address=10.99.0.10 secret=OneGate-Lab-Chave-2026 timeout=3s
/user aaa set use-radius=yes default-group=read accounting=yes
