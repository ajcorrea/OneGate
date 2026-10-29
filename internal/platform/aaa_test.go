package platform

import (
	"context"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/ajcorrea/onegate/internal/passhash"
	"github.com/ajcorrea/onegate/internal/policy"
	"github.com/ajcorrea/onegate/internal/totp"
)

type simOut struct {
	Result struct {
		Allowed   bool          `json:"allowed"`
		Rule      string        `json:"rule"`
		Reason    string        `json:"reason"`
		PrivLevel int           `json:"priv_level"`
		Trail     []policy.Step `json:"trail"`
		MFA       struct {
			Required bool `json:"required"`
		} `json:"mfa"`
	} `json:"result"`
	Warnings []string       `json:"warnings"`
	Versions map[string]int `json:"versions"`
}

func TestAAARulesFlow(t *testing.T) {
	s, hs, clk := testServer(t)
	ctx := context.Background()
	const adminPW, juliaPW, devPW = "senha-do-admin-123", "senha-da-julia-123", "senha-equipamento-1"
	if _, err := s.CreatePanelUser(ctx, System, NewPanelUser{Login: "admin", Name: "Admin", Password: adminPW, TypeKey: "global_admin"}); err != nil {
		t.Fatal(err)
	}
	admin := newClient(t, hs)
	var adminSecret string
	admin.login(clk, "admin@onegate.systems", adminPW, &adminSecret)

	var nsf, slg Customer
	admin.do("POST", "/api/customers", map[string]any{"code": "NSF", "name": "NetSul Fibra", "domain": "netsulfibra.com.br", "color": "#2563eb"}, &nsf)
	admin.do("POST", "/api/customers", map[string]any{"code": "SLG", "name": "Serra Logística", "domain": "serralogistica.com.br", "color": "#6D28D9"}, &slg)
	var types []AccessType
	admin.do("GET", "/api/access-types", nil, &types)
	tid := map[string]string{}
	for _, ty := range types {
		if ty.Key != nil {
			tid[*ty.Key] = ty.ID
		}
	}

	// Pessoas: Júlia (admin NSF), Pedro (técnico NSF), Marcos (técnico global), Sérgio (técnico SLG)
	person := func(name string, cid *string, user string) Person {
		var p Person
		body := map[string]any{"name": name}
		if cid != nil {
			body["customer_id"] = *cid
		}
		if st := admin.do("POST", "/api/people", body, &p); st != 201 {
			t.Fatalf("pessoa %s: %d", name, st)
		}
		if user != "" {
			if st := admin.do("PUT", "/api/people/"+p.ID+"/device", map[string]any{"username": user, "password": devPW}, &p); st != 200 {
				t.Fatalf("acesso aos equipamentos %s: %d", name, st)
			}
		}
		return p
	}
	julia := person("Júlia Santos", &nsf.ID, "")
	admin.do("PUT", "/api/people/"+julia.ID+"/panel", map[string]any{"login": "julia", "password": juliaPW, "access_type_id": tid["customer_admin"]}, nil)
	pedro := person("Pedro Lima", &nsf.ID, "pedro.lima")
	marcos := person("Marcos Ribeiro", nil, "marcos")
	sergio := person("Sérgio Alves", &slg.ID, "sergio")
	var pedroTOTP map[string]string
	admin.do("POST", "/api/people/"+pedro.ID+"/device/totp", map[string]any{}, &pedroTOTP)

	// Objetos globais (Admin global)
	obj := func(c *client, cid *string, kind, name string, data any) string {
		t.Helper()
		var out map[string]string
		body := map[string]any{"kind": kind, "name": name, "data": data}
		if cid != nil {
			body["customer_id"] = *cid
		}
		if st := c.do("POST", "/api/aaa/objects", body, &out); st != 201 {
			t.Fatalf("objeto %s: %d %v", name, st, out)
		}
		return out["id"]
	}
	gNOC := obj(admin, nil, kindUserGroup, "NOC", nil)
	dgCore := obj(admin, nil, kindDeviceGroup, "Núcleo", map[string]any{"mfa": "totp", "trust_window_seconds": 3600})
	dgAccess := obj(admin, nil, kindDeviceGroup, "Acesso", map[string]any{"mfa": "off"})
	netNOC := obj(admin, nil, kindNetwork, "Rede NOC", map[string]any{"cidrs": []string{"10.20.0.0/16", " 172.16.50.7 "}})
	pFull := obj(admin, nil, kindProfile, "Acesso total", map[string]any{"priv_level": 15})
	pRead := obj(admin, nil, kindProfile, "Somente leitura", map[string]any{"priv_level": 5, "allow": []string{"display *", "show *"}, "deny": []string{"display current-configuration *"}})
	sBiz := obj(admin, nil, kindSchedule, "Comercial", map[string]any{"windows": []map[string]any{{"days": []int{1, 2, 3, 4, 5}, "start": "08:00", "end": "18:00"}}})

	// Validações de objeto
	for _, bad := range []map[string]any{
		{"kind": kindNetwork, "name": "Vazia", "data": map[string]any{"cidrs": []string{}}},
		{"kind": kindNetwork, "name": "Errada", "data": map[string]any{"cidrs": []string{"10.0.0.0/33"}}},
		{"kind": kindProfile, "name": "Priv", "data": map[string]any{"priv_level": 16}},
		{"kind": kindSchedule, "name": "Hora", "data": map[string]any{"windows": []map[string]any{{"days": []int{8}, "start": "08:00", "end": "18:00"}}}},
		{"kind": kindDeviceGroup, "name": "Campo", "data": map[string]any{"mfa": "totp", "extra": 1}},
		{"kind": kindNetwork, "name": "Rede NOC", "data": map[string]any{"cidrs": []string{"10.0.0.0/8"}}}, // repetido
		{"kind": "outro", "name": "X1"},
		{"kind": kindUserGroup, "name": "a@b"},
	} {
		if st := admin.do("POST", "/api/aaa/objects", bad, nil); st != 400 && st != 409 {
			t.Fatalf("objeto inválido aceito %v: %d", bad, st)
		}
	}
	admin.do("PUT", "/api/aaa/objects/"+gNOC+"/members", map[string]any{"person_ids": []string{marcos.ID}}, nil)
	if st := admin.do("PUT", "/api/aaa/objects/"+gNOC+"/members", map[string]any{"person_ids": []string{pedro.ID}}, nil); st != 400 {
		t.Fatalf("técnico do cliente em grupo global: %d", st)
	}

	// Júlia (admin do cliente) cria objetos e equipamentos da NSF, mas não globais
	jc := newClient(t, hs)
	var jSecret string
	jc.login(clk, "julia@netsulfibra.com.br", juliaPW, &jSecret)
	if st := jc.do("POST", "/api/aaa/objects", map[string]any{"kind": kindNetwork, "name": "Qualquer", "data": map[string]any{"cidrs": []string{"0.0.0.0/0"}}}, nil); st != 403 {
		t.Fatalf("admin do cliente criou objeto global: %d", st)
	}
	if st := jc.do("POST", "/api/aaa/objects", map[string]any{"customer_id": nsf.ID, "kind": kindNetwork, "name": "rede noc", "data": map[string]any{"cidrs": []string{"10.1.0.0/16"}}}, nil); st != 409 {
		t.Fatalf("nome igual a objeto global: %d", st)
	}
	gN1 := obj(jc, &nsf.ID, kindUserGroup, "Suporte N1", nil)
	netVPN := obj(jc, &nsf.ID, kindNetwork, "VPN técnicos", map[string]any{"cidrs": []string{"172.16.60.0/24"}})
	if st := jc.do("PUT", "/api/aaa/objects/"+gN1+"/members", map[string]any{"person_ids": []string{pedro.ID}}, nil); st != 204 {
		t.Fatalf("membros: %d", st)
	}
	if st := jc.do("PUT", "/api/aaa/objects/"+gN1+"/members", map[string]any{"person_ids": []string{sergio.ID}}, nil); st != 400 {
		t.Fatalf("técnico de outro cliente no grupo: %d", st)
	}

	var bng, sw map[string]string
	if st := jc.do("POST", "/api/aaa/devices", map[string]any{"customer_id": nsf.ID, "name": "bng-01", "address": "10.0.0.1", "vendor": "Huawei", "model": "NE8000",
		"group_ids": []string{dgCore}}, &bng); st != 201 || len(bng["secret"]) != 24 {
		t.Fatalf("equipamento: %d %v", st, bng)
	}
	jc.do("POST", "/api/aaa/devices", map[string]any{"customer_id": nsf.ID, "name": "sw-acesso", "address": "10.0.8.0/24", "vendor": "Datacom", "group_ids": []string{dgAccess}}, &sw)
	if st := jc.do("POST", "/api/aaa/devices", map[string]any{"customer_id": nsf.ID, "name": "bng-02", "address": "10.0.0.1/32"}, nil); st != 409 {
		t.Fatalf("endereço repetido: %d", st)
	}
	if st := jc.do("POST", "/api/aaa/devices", map[string]any{"customer_id": slg.ID, "name": "srv", "address": "10.9.0.1"}, nil); st != 403 {
		t.Fatalf("equipamento em outro cliente: %d", st)
	}
	var devs []aaaDevice
	jc.do("GET", "/api/aaa/devices?customer_id="+nsf.ID, nil, &devs)
	if len(devs) != 2 || devs[0].Address != "10.0.0.1" || devs[1].Address != "10.0.8.0/24" || devs[0].GroupIDs[0] != dgCore {
		t.Fatalf("lista de equipamentos: %+v", devs)
	}

	// Regras globais (Admin global): NOC a partir da Rede NOC
	if st := jc.do("PUT", "/api/aaa/rules", map[string]any{"rules": []any{}}, nil); st != 403 {
		t.Fatalf("admin do cliente editou regras globais: %d", st)
	}
	globalRules := []map[string]any{{"name": "NOC: acesso total", "action": "allow", "who": []string{"group:" + gNOC}, "where": []string{"all"},
		"from": []string{"net:" + netNOC}, "what": "profile:" + pFull, "mfa": "totp"}}
	if st := admin.do("PUT", "/api/aaa/rules", map[string]any{"rules": globalRules}, nil); st != 200 {
		t.Fatalf("regras globais: %d", st)
	}
	// Regra global não pode usar grupo de cliente
	if st := admin.do("PUT", "/api/aaa/rules", map[string]any{"rules": []map[string]any{{"name": "X", "action": "allow", "who": []string{"group:" + gN1}, "where": []string{"all"}, "from": []string{"all"}, "what": "none"}}}, nil); st != 400 {
		t.Fatalf("regra global com grupo do cliente: %d", st)
	}

	// Rascunho do cliente: uma regra completa e uma incompleta (sem De onde)
	type rule = map[string]any
	draft := []rule{
		{"name": "Suporte N1: leitura", "action": "allow", "who": []string{"group:" + gN1}, "where": []string{"group:" + dgCore, "group:" + dgAccess},
			"from": []string{"net:" + netVPN, "net:" + netNOC}, "what": "profile:" + pRead, "when": []string{"schedule:" + sBiz}, "mfa": "device"},
		{"name": "Rascunho sem origem", "action": "allow", "who": []string{"all"}, "where": []string{"all"}, "from": []string{}, "what": "profile:" + pFull},
	}
	var saved []AAARule
	if st := jc.do("PUT", "/api/aaa/rules?customer_id="+nsf.ID, map[string]any{"rules": draft}, &saved); st != 200 || len(saved) != 2 {
		t.Fatalf("rascunho: %d %+v", st, saved)
	}
	// Grupo de técnicos global numa regra do cliente: recusado
	bad := append([]rule{{"name": "Global no cliente", "action": "allow", "who": []string{"group:" + gNOC}, "where": []string{"all"}, "from": []string{"all"}, "what": "none"}}, draft...)
	if st := jc.do("PUT", "/api/aaa/rules?customer_id="+nsf.ID, map[string]any{"rules": bad}, nil); st != 400 {
		t.Fatalf("grupo global em regra do cliente: %d", st)
	}

	// Simulador (rascunho): quarta 10h pela VPN
	wed10 := "2026-10-28T10:00"
	sim := func(c *client, mode, user, dev, src, at, cmd string) simOut {
		t.Helper()
		var out simOut
		if st := c.do("POST", "/api/aaa/simulate", map[string]any{"customer_id": nsf.ID, "mode": mode, "user": user, "device_id": dev,
			"source": src, "at": at, "command": cmd}, &out); st != 200 {
			t.Fatalf("simulador: %d", st)
		}
		return out
	}
	r := sim(jc, "draft", "pedro.lima", bng["id"], "172.16.60.9", wed10, "display interface")
	if !r.Result.Allowed || r.Result.Rule != "Suporte N1: leitura" || r.Result.PrivLevel != 5 || !r.Result.MFA.Required {
		t.Fatalf("simulação permitida: %+v", r.Result)
	}
	if len(r.Result.Trail) != 3 || r.Result.Trail[0].Status != "miss" || r.Result.Trail[1].Status != "hit" || r.Result.Trail[2].Status != "skip" {
		t.Fatalf("rastro: %+v", r.Result.Trail)
	}
	if r := sim(jc, "draft", "pedro.lima", bng["id"], "172.16.60.9", wed10, "display current-configuration"); r.Result.Allowed {
		t.Fatal("comando proibido liberado")
	}
	// Fora do horário: regra completa falha e a incompleta é ignorada (nunca libera)
	r = sim(jc, "draft", "pedro.lima", sw["id"], "172.16.60.9", "2026-10-28T22:00", "")
	if r.Result.Allowed || r.Result.Trail[2].Status != "incomplete" {
		t.Fatalf("fora do horário: %+v", r.Result)
	}
	// Acesso desligado no grupo Acesso: sem MFA
	if r := sim(jc, "draft", "pedro.lima@netsulfibra.com.br", sw["id"], "172.16.60.9", wed10, ""); !r.Result.Allowed || r.Result.MFA.Required {
		t.Fatalf("MFA herdado do grupo Acesso: %+v", r.Result)
	}
	// Publicado: ainda não há nada publicado do cliente → só a regra global vale
	if r := sim(jc, "published", "pedro.lima", bng["id"], "172.16.60.9", wed10, ""); r.Result.Allowed {
		t.Fatalf("publicado sem regras do cliente liberou: %+v", r.Result)
	}

	// Publicar com regra incompleta é recusado
	var perr map[string]string
	if st := jc.do("POST", "/api/aaa/publish?customer_id="+nsf.ID, map[string]any{"note": "primeira"}, &perr); st != 400 || !strings.Contains(perr["error"], "Rascunho sem origem") {
		t.Fatalf("publicar incompleta: %d %v", st, perr)
	}
	jc.do("PUT", "/api/aaa/rules?customer_id="+nsf.ID, map[string]any{"rules": []any{map[string]any{
		"id": saved[0].ID, "name": saved[0].Name, "action": "allow", "who": saved[0].Who, "where": saved[0].Where, "from": saved[0].From,
		"what": saved[0].What, "when": saved[0].When, "mfa": "device"}}}, nil)
	var pub map[string]int
	if st := jc.do("POST", "/api/aaa/publish?customer_id="+nsf.ID, map[string]any{"note": "primeira"}, &pub); st != 200 || pub["version"] != 1 {
		t.Fatalf("publicar: %d %v", st, pub)
	}
	if st := jc.do("POST", "/api/aaa/publish?customer_id="+nsf.ID, map[string]any{}, nil); st != 400 {
		t.Fatalf("publicar sem mudanças: %d", st)
	}
	if st := admin.do("POST", "/api/aaa/publish", map[string]any{"note": "NOC"}, &pub); st != 200 || pub["version"] != 1 {
		t.Fatalf("publicar global: %d", st)
	}
	r = sim(jc, "published", "pedro.lima", bng["id"], "172.16.60.9", wed10, "")
	if !r.Result.Allowed || r.Versions["customer"] != 1 || r.Versions["global"] != 1 {
		t.Fatalf("publicado: %+v %v", r.Result, r.Versions)
	}

	// Vista das regras: diff vazio, rótulos resolvidos
	var view struct {
		Global, Customer ruleScopeView
		Labels           map[string]RefLabel `json:"labels"`
	}
	jc.do("GET", "/api/aaa/rules?customer_id="+nsf.ID, nil, &view)
	if len(view.Customer.Diff) != 0 || view.Customer.Publication.Version != 1 || view.Global.CanEdit || !view.Customer.CanPublish {
		t.Fatalf("vista: %+v", view)
	}
	if l := view.Labels["who|group:"+gN1]; l.Label != "Grupo Suporte N1 @netsulfibra.com.br" {
		t.Fatalf("rótulo: %+v", l)
	}

	// Objeto em uso não pode ser apagado; objeto livre pode
	if st := admin.do("DELETE", "/api/aaa/objects/"+netNOC, map[string]any{}, nil); st != 409 {
		t.Fatalf("apagar objeto em uso: %d", st)
	}
	free := obj(admin, nil, kindSchedule, "Plantão", map[string]any{"windows": []map[string]any{{"days": []int{1, 2, 3, 4, 5, 6, 7}, "start": "18:00", "end": "08:00"}}})
	if st := admin.do("DELETE", "/api/aaa/objects/"+free, map[string]any{}, nil); st != 204 {
		t.Fatalf("apagar objeto livre: %d", st)
	}

	// Busca: usuários só com 3 letras; grupos e pré-definidos sempre
	var items []searchItem
	jc.do("GET", "/api/aaa/search?customer_id="+nsf.ID+"&field=who&q=", nil, &items)
	if len(items) != 3 || items[0].Ref != "all" || items[2].Ref != "group:"+gN1 {
		t.Fatalf("busca vazia: %+v", items)
	}
	jc.do("GET", "/api/aaa/search?customer_id="+nsf.ID+"&field=who&q=ped", nil, &items)
	if len(items) != 1 || items[0].Ref != "user:"+pedro.ID {
		t.Fatalf("busca ped: %+v", items)
	}
	jc.do("GET", "/api/aaa/search?customer_id="+nsf.ID+"&field=who&q=ser", nil, &items)
	if len(items) != 0 {
		t.Fatalf("busca vazou técnico de outro cliente: %+v", items)
	}
	jc.do("GET", "/api/aaa/search?customer_id="+nsf.ID+"&field=from&q=noc", nil, &items)
	if len(items) != 1 || items[0].Ref != "net:"+netNOC {
		t.Fatalf("busca rede (sem acento): %+v", items)
	}
	jc.do("GET", "/api/aaa/search?customer_id="+nsf.ID+"&field=where&q=huawei", nil, &items)
	if len(items) != 2 || items[0].Ref != "vendor:Huawei" {
		t.Fatalf("busca fabricante: %+v", items)
	}

	// Isolamento: Júlia não vê nada da SLG
	if st := jc.do("GET", "/api/aaa/rules?customer_id="+slg.ID, nil, nil); st != 403 {
		t.Fatalf("regras de outro cliente: %d", st)
	}
	if st := jc.do("GET", "/api/aaa/devices?customer_id="+slg.ID, nil, nil); st != 403 {
		t.Fatalf("equipamentos de outro cliente: %d", st)
	}

	// Rotação da chave
	var rot map[string]string
	if st := jc.do("POST", "/api/aaa/devices/"+bng["id"]+"/rotate-secret", map[string]any{}, &rot); st != 200 || rot["secret"] == bng["secret"] {
		t.Fatalf("rotação: %d", st)
	}

	// Exportação assinada: o motor do Edge aceita e decide igual ao simulador
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	priv, err := PolicySigningKey("AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=")
	if err != nil {
		t.Fatal(err)
	}
	pkg, warnings, err := s.ExportPolicy(ctx, "nsf", func(p *policy.Policy) ([]byte, error) { return policy.Sign(p, priv) })
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 0 {
		t.Fatalf("avisos: %v", warnings)
	}
	doc, err := policy.Verify(pkg, priv.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	eng, err := policy.Compile(doc)
	if err != nil {
		t.Fatal(err)
	}
	// Segredos reais no pacote; técnico de outro cliente fora
	if d, _ := eng.DeviceByName("bng-01"); d.Secret != rot["secret"] {
		t.Fatal("chave do equipamento não confere")
	}
	u, ok := eng.ResolveUser("pedro.lima")
	if !ok || u.TOTPSecret != pedroTOTP["secret"] {
		t.Fatal("TOTP do técnico não confere")
	}
	if ok, _ := passhash.Verify(devPW, u.PasswordHash); !ok {
		t.Fatal("hash do técnico não confere")
	}
	if _, ok := eng.ResolveUser("sergio@serralogistica.com.br"); ok {
		t.Fatal("técnico de outro cliente vazou para a política")
	}
	if _, ok := eng.ResolveUser("marcos"); !ok {
		t.Fatal("técnico global alcançado por regra global deveria estar na política")
	}
	sp, _ := time.LoadLocation("America/Sao_Paulo")
	d, _ := eng.DeviceByName("bng-01")
	res := eng.Evaluate(policy.Request{User: "marcos", Device: d, Source: "172.16.50.7", Time: time.Date(2026, 10, 28, 3, 0, 0, 0, sp)})
	if !res.Allowed || res.Rule != "NOC: acesso total" || res.PrivLevel != 15 {
		t.Fatalf("NOC no Edge: %+v", res)
	}
	if code, _ := totp.Code(u.TOTPSecret, time.Now()); len(code) != 6 {
		t.Fatal("TOTP")
	}

	// Auditoria registrou as ações AAA
	var events []map[string]any
	admin.do("GET", "/api/audit?limit=200", nil, &events)
	seen := map[string]bool{}
	for _, e := range events {
		seen[e["action"].(string)] = true
	}
	for _, a := range []string{"aaa.objeto_criado", "aaa.equipamento_criado", "aaa.rascunho_salvo", "aaa.regras_publicadas", "aaa.equipamento_chave_rotacionada", "aaa.politica_exportada", "aaa.objeto_apagado"} {
		if !seen[a] {
			t.Errorf("auditoria sem %s", a)
		}
	}
}

func TestCustomerTimezone(t *testing.T) {
	s, hs, clk := testServer(t)
	if _, err := s.CreatePanelUser(context.Background(), System, NewPanelUser{Login: "admin", Name: "Admin", Password: "senha-do-admin-123", TypeKey: "global_admin"}); err != nil {
		t.Fatal(err)
	}
	admin := newClient(t, hs)
	var sec string
	admin.login(clk, "admin@onegate.systems", "senha-do-admin-123", &sec)
	var c Customer
	if st := admin.do("POST", "/api/customers", map[string]any{"code": "VLC", "name": "Vale Conecta", "domain": "valeconecta.com.br", "color": "#0F7B53"}, &c); st != 201 || c.Timezone != "America/Sao_Paulo" {
		t.Fatalf("fuso padrão: %d %q", st, c.Timezone)
	}
	if st := admin.do("PATCH", "/api/customers/"+c.ID, map[string]any{"timezone": "America/Manaus"}, &c); st != 200 || c.Timezone != "America/Manaus" {
		t.Fatalf("trocar fuso: %d %q", st, c.Timezone)
	}
	if st := admin.do("PATCH", "/api/customers/"+c.ID, map[string]any{"timezone": "Lua/Base"}, nil); st != 400 {
		t.Fatalf("fuso inválido: %d", st)
	}
}
