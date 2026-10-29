#!/usr/bin/env python3
"""Popula o ONE GATE do laboratório pela API (só biblioteca padrão do Python).

Cria o cliente LAB, técnicos com TOTP, objetos, equipamentos do EVE-NG, regras globais e do
cliente, e publica as duas. Grava as credenciais em credenciais-lab.txt (permissão 600).

Uso: python3 popular-lab.py --url http://127.0.0.1:8080 --login admin@onegate.systems \
       --senha '...' [--totp-secret SEGREDO_DO_ADMIN] [--chave CHAVE_DOS_EQUIPAMENTOS]
"""
import argparse
import base64
import hashlib
import hmac
import http.cookiejar
import json
import os
import secrets
import struct
import sys
import time
import urllib.error
import urllib.request

LAB_DOMINIO = "lab.ontelecom.io"
LAB_REDE = "10.99.0"


def totp(secret: str, offset: int = 0) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    msg = struct.pack(">Q", int(time.time()) // 30 + offset)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    o = h[-1] & 15
    return "%06d" % ((struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % 1000000)


class API:
    def __init__(self, url: str):
        self.url = url.rstrip("/")
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def req(self, method, path, body=None):
        data = json.dumps({} if body is None and method != "GET" else body).encode() if method != "GET" else None
        r = urllib.request.Request(self.url + path, data=data, method=method, headers={"Content-Type": "application/json"})
        try:
            with self.op.open(r) as resp:
                txt = resp.read().decode()
        except urllib.error.HTTPError as e:
            raise SystemExit(f"erro: {method} {path}: {e.code} {e.read().decode()}")
        return json.loads(txt) if txt else None

    def login(self, login, senha, totp_secret=None):
        r = self.req("POST", "/api/auth/login", {"login": login, "password": senha})
        novo = r.get("next") == "totp_setup"
        if novo:
            totp_secret = r["secret"]
        if not totp_secret:
            raise SystemExit("erro: o admin já tem TOTP; informe --totp-secret ou rode antes do primeiro login no painel")
        # Usa o próximo passo de 30 s: o anti-reuso recusaria um código já usado.
        out = self.req("POST", "/api/auth/totp", {"code": totp(totp_secret, 1)})
        return totp_secret, novo, (out or {}).get("recovery_codes")


def senha_lab() -> str:
    return "Lab-" + secrets.token_urlsafe(9)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8080")
    ap.add_argument("--login", required=True)
    ap.add_argument("--senha", required=True)
    ap.add_argument("--totp-secret")
    ap.add_argument("--chave", default=os.environ.get("LAB_CHAVE", "OneGate-Lab-Chave-2026"), help="chave TACACS+ dos equipamentos (mín. 16)")
    ap.add_argument("--painel-url", help="endereço do painel para o arquivo de credenciais (padrão: --url)")
    ap.add_argument("--saida", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "credenciais-lab.txt"))
    a = ap.parse_args()
    if len(a.chave) < 16:
        raise SystemExit("erro: a chave precisa de pelo menos 16 caracteres")

    api = API(a.url)
    admin_totp, admin_novo, recovery = api.login(a.login, a.senha, a.totp_secret)
    if any(c["code"] == "LAB" for c in api.req("GET", "/api/customers")):
        raise SystemExit("erro: o cliente LAB já existe; este script é para um banco novo")

    lab = api.req("POST", "/api/customers", {"code": "LAB", "name": "Laboratório ON TELECOM", "domain": LAB_DOMINIO,
                                             "segment": "provedor", "color": "#1E4087"})
    cid = lab["id"]

    def pessoa(nome, usuario, cliente=None, com_totp=True):
        corpo = {"name": nome}
        if cliente:
            corpo["customer_id"] = cliente
        p = api.req("POST", "/api/people", corpo)
        senha = senha_lab()
        api.req("PUT", f"/api/people/{p['id']}/device", {"username": usuario, "password": senha})
        t = api.req("POST", f"/api/people/{p['id']}/device/totp") if com_totp else {"secret": "", "otpauth_uri": ""}
        dom = LAB_DOMINIO if cliente else "onegate.systems"
        return {"id": p["id"], "usuario": f"{usuario}@{dom}", "curto": usuario, "senha": senha, "totp": t["secret"], "uri": t["otpauth_uri"]}

    noc = pessoa("NOC Laboratório", "noc.lab")
    sup = pessoa("Suporte N1 Laboratório", "suporte.n1", cid)
    ter = pessoa("Terceiro Redes Ltda", "terceiro", cid)
    bkp = pessoa("Conta de serviço de backup", "backup", cid, com_totp=False)

    def obj(kind, nome, data, cliente=None, desc=""):
        corpo = {"kind": kind, "name": nome, "data": data, "description": desc}
        if cliente:
            corpo["customer_id"] = cliente
        return api.req("POST", "/api/aaa/objects", corpo)["id"]

    # Objetos globais
    g_noc = obj("user_group", "NOC", {}, desc="operadores globais")
    api.req("PUT", f"/api/aaa/objects/{g_noc}/members", {"person_ids": [noc["id"]]})
    dg = {
        "Núcleo": obj("device_group", "Núcleo", {"mfa": "totp", "trust_window_seconds": 3600}),
        "Borda": obj("device_group", "Borda", {"mfa": "inherit"}),
        "Acesso": obj("device_group", "Acesso", {"mfa": "off"}),
    }
    n_noc = obj("network", "Rede NOC (lab)", {"cidrs": [f"{LAB_REDE}.10"]}, desc="VM ONE GATE")
    p_total = obj("profile", "Acesso total", {"priv_level": 15})
    p_leitura = obj("profile", "Somente leitura", {"priv_level": 5,
        "allow": ["show *", "display *", "ping *", "traceroute *", "tracert *", "terminal length *", "screen-length *", "quit", "exit", "logout"],
        "deny": ["show running-config *", "display current-configuration *"]})
    p_ops = obj("profile", "Operação sem roteamento", {"priv_level": 15, "default": "allow",
        "deny": ["router bgp *", "router ospf *", "router isis *", "bgp *", "ospf *", "isis *", "route-policy *", "route-map *", "undo bgp *", "no router *"]})
    p_bkp = obj("profile", "Backup de configuração", {"priv_level": 15,
        "allow": ["terminal length 0", "screen-length 0 temporary", "show running-config", "display current-configuration", "quit", "exit", "logout"]})
    s_com = obj("schedule", "Comercial", {"windows": [{"days": [1, 2, 3, 4, 5], "start": "08:00", "end": "18:00"}]})

    # Objetos do cliente LAB
    g_sup = obj("user_group", "Suporte N1", {}, cid)
    g_ter = obj("user_group", "Terceirizados", {}, cid)
    g_svc = obj("user_group", "Contas de serviço", {}, cid)
    api.req("PUT", f"/api/aaa/objects/{g_sup}/members", {"person_ids": [sup["id"]]})
    api.req("PUT", f"/api/aaa/objects/{g_ter}/members", {"person_ids": [ter["id"]]})
    api.req("PUT", f"/api/aaa/objects/{g_svc}/members", {"person_ids": [bkp["id"]]})
    n_note = obj("network", "Notebook do técnico", {"cidrs": [f"{LAB_REDE}.50"]}, cid)

    equipamentos = [
        ("huawei-ne40e", f"{LAB_REDE}.1", "Huawei", "NE40E", ["Núcleo"], "prompt"),
        ("arista-veos", f"{LAB_REDE}.2", "Arista", "vEOS-lab", ["Acesso"], "prompt"),
        ("cisco-iosv", f"{LAB_REDE}.3", "Cisco", "IOSv", ["Borda"], "prompt"),
        ("mikrotik-chr", f"{LAB_REDE}.4", "MikroTik", "CHR", ["Borda"], "append"),
    ]
    for nome, ip, fab, modelo, grupos, entrada in equipamentos:
        api.req("POST", "/api/aaa/devices", {"customer_id": cid, "name": nome, "address": ip, "vendor": fab, "model": modelo,
                                             "group_ids": [dg[g] for g in grupos], "code_entry": entrada, "secret": a.chave})

    # Regras globais
    api.req("PUT", "/api/aaa/rules", {"rules": [
        {"name": "NOC: acesso total", "action": "allow", "who": [f"group:{g_noc}"], "where": ["all"], "from": [f"net:{n_noc}"],
         "what": f"profile:{p_total}", "when": ["always"], "mfa": "totp"},
    ]})
    api.req("POST", "/api/aaa/publish", {"note": "Laboratório: regras globais"})
    # Regras do cliente
    api.req("PUT", f"/api/aaa/rules?customer_id={cid}", {"rules": [
        {"name": "Backup de configuração", "action": "allow", "who": [f"group:{g_svc}"], "where": ["all"], "from": [f"net:{n_noc}"],
         "what": f"profile:{p_bkp}", "mfa": "none"},
        {"name": "Terceirizados fora do núcleo", "action": "deny", "who": [f"group:{g_ter}"], "where": [f"group:{dg['Núcleo']}"], "from": ["all"]},
        {"name": "Suporte N1: somente leitura", "action": "allow", "who": [f"group:{g_sup}"], "where": ["all"], "from": [f"net:{n_note}"],
         "what": f"profile:{p_leitura}", "when": ["always"], "mfa": "device"},
        {"name": "Terceirizados: horário comercial", "action": "allow", "who": [f"group:{g_ter}"], "where": [f"group:{dg['Acesso']}", f"group:{dg['Borda']}"],
         "from": ["all"], "what": f"profile:{p_ops}", "when": [f"schedule:{s_com}"], "mfa": "totp"},
    ]})
    api.req("POST", f"/api/aaa/publish?customer_id={cid}", {"note": "Laboratório: primeira versão"})

    linhas = [
        "ONE GATE — credenciais do laboratório (NÃO use em produção)",
        "=" * 60,
        f"Painel: {a.painel_url or a.url}   login: {a.login}",
    ]
    if admin_novo:
        linhas += [f"TOTP do painel (cadastre no app autenticador): {admin_totp}",
                   f"  otpauth://totp/ONE%20GATE%20(painel):{a.login}?secret={admin_totp}&issuer=ONE%20GATE",
                   "Códigos de recuperação do painel: " + " ".join(recovery or [])]
    linhas += ["", f"Chave TACACS+ de todos os equipamentos: {a.chave}", "",
               "Técnicos (equipamentos). Cadastre cada TOTP no app autenticador:"]
    for t, papel in ((noc, "NOC global — tudo, só a partir de 10.99.0.10, TOTP sempre"),
                     (sup, "Suporte N1 — somente leitura, só a partir de 10.99.0.50"),
                     (ter, "Terceirizado — negado no núcleo; Acesso/Borda em horário comercial, TOTP"),
                     (bkp, "Conta de serviço — backup, só a partir de 10.99.0.10, sem MFA")):
        linhas += [f"- {t['usuario']}  (pode digitar só '{t['curto']}')", f"    {papel}", f"    senha: {t['senha']}"]
        if t["totp"]:
            linhas += [f"    TOTP:  {t['totp']}", f"    {t['uri']}"]
    with open(os.open(a.saida, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
        f.write("\n".join(linhas) + "\n")
    print(f"Laboratório criado: cliente LAB, 4 técnicos, {len(equipamentos)} equipamentos, regras publicadas.")
    print(f"Credenciais em {a.saida}")


if __name__ == "__main__":
    main()
