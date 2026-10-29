// Package policy define a política de acesso que a nuvem publica para os Edges de um cliente
// e o motor que decide autenticação, MFA e autorização de comandos.
//
// A política é um documento único por cliente, gerado pela nuvem a partir dos objetos e das
// regras AAA (globais e do cliente). O Edge nunca a edita: só recebe versões novas, assinadas.
//
// Regras: a primeira que corresponder decide; sem correspondência, nega. Cada regra tem
// Quem, Onde, De onde, O que, Quando e MFA. Um campo obrigatório vazio não libera nada: a regra
// fica incompleta e é ignorada. Para liberar tudo é preciso escolher o objeto "all" (Todos).
package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// FormatVersion é a versão do formato do documento.
const FormatVersion = 2

// MFAMode é a configuração de MFA de um nível (cliente, grupo de equipamentos ou equipamento).
type MFAMode string

const (
	// MFAInherit segue o nível acima (válido para grupo e equipamento).
	MFAInherit MFAMode = "inherit"
	// MFAOff dispensa o MFA.
	MFAOff MFAMode = "off"
	// MFATOTP exige código TOTP.
	MFATOTP MFAMode = "totp"
)

// CodeEntry define como o técnico informa o código TOTP no equipamento.
type CodeEntry string

const (
	// EntryPrompt pede o código num segundo prompt depois da senha (TACACS+ ASCII).
	EntryPrompt CodeEntry = "prompt"
	// EntryAppend espera a senha seguida dos 6 dígitos no mesmo campo.
	EntryAppend CodeEntry = "append"
)

// Action é o resultado de uma regra.
type Action string

const (
	Allow Action = "allow"
	Deny  Action = "deny"
)

// Escopo de uma regra.
const (
	ScopeGlobal   = "global"
	ScopeCustomer = "customer"
)

// MFA de uma regra.
const (
	RuleMFATOTP   = "totp"   // sempre exige TOTP
	RuleMFADevice = "device" // segue cliente → grupo → equipamento (padrão)
	RuleMFANone   = "none"   // só senha
)

// Objetos pré-definidos usados nas referências das regras.
const (
	RefAll    = "all"    // Todos (usuários do escopo, equipamentos, qualquer IP)
	RefNone   = "none"   // Ninguém / Nenhum / Nenhum comando
	RefAlways = "always" // Quando: sempre
	RefNever  = "never"  // Quando: nunca (regra desligada)
)

// Policy é o documento completo de um cliente.
type Policy struct {
	Format int `json:"format"`
	// Version cresce a cada documento gerado; o Edge recusa versão menor que a atual.
	Version int64 `json:"version"`
	// Versões publicadas das regras globais e do cliente que geraram o documento.
	GlobalRulesVersion   int    `json:"global_rules_version,omitempty"`
	CustomerRulesVersion int    `json:"customer_rules_version,omitempty"`
	GeneratedAt          string `json:"generated_at,omitempty"`
	// GlobalDomain é o domínio dos acessos globais (ex.: onegate.systems).
	GlobalDomain string        `json:"global_domain"`
	Customer     Customer      `json:"customer"`
	DeviceGroups []DeviceGroup `json:"device_groups"`
	Devices      []Device      `json:"devices"`
	UserGroups   []UserGroup   `json:"user_groups"`
	Users        []User        `json:"users"`
	Networks     []Network     `json:"networks"`
	Profiles     []Profile     `json:"profiles"`
	Schedules    []Schedule    `json:"schedules"`
	Rules        []Rule        `json:"rules"`
}

// Customer guarda os padrões do cliente.
type Customer struct {
	Code   string `json:"code"`
	Name   string `json:"name"`
	Domain string `json:"domain"`
	// MFA padrão do cliente: "off" ou "totp".
	MFA MFAMode `json:"mfa"`
	// Janela de confiança padrão, em segundos. 0 = sempre pedir o código.
	TrustWindowSeconds int `json:"trust_window_seconds"`
	// Timezone dos horários (padrão America/Sao_Paulo).
	Timezone string `json:"timezone,omitempty"`
}

// DeviceGroup agrupa equipamentos (ex.: Núcleo, Borda, Acesso).
type DeviceGroup struct {
	Name               string  `json:"name"`
	MFA                MFAMode `json:"mfa"`
	TrustWindowSeconds *int    `json:"trust_window_seconds,omitempty"`
}

// Device é um equipamento ou servidor que autentica no Edge.
type Device struct {
	Name string `json:"name"`
	// Address é o IP de origem dos pacotes (NAS) ou uma faixa CIDR.
	Address string `json:"address"`
	// Groups: o primeiro grupo define a herança de MFA; todos valem nas regras.
	Groups []string `json:"groups,omitempty"`
	Vendor string   `json:"vendor,omitempty"`
	MFA    MFAMode  `json:"mfa"`
	// CodeEntry padrão: prompt.
	CodeEntry          CodeEntry `json:"code_entry,omitempty"`
	TrustWindowSeconds *int      `json:"trust_window_seconds,omitempty"`
	// Secret é a chave compartilhada TACACS+/RADIUS deste equipamento.
	Secret string `json:"secret"`
}

// UserGroup agrupa técnicos. O nome inclui o domínio: "Suporte N1@netsulfibra.com.br".
type UserGroup struct {
	Name string `json:"name"`
}

// User é um técnico ou conta de serviço. Username é sempre usuario@dominio.
type User struct {
	Username     string   `json:"username"`
	Name         string   `json:"name,omitempty"`
	PasswordHash string   `json:"password_hash"`
	TOTPSecret   string   `json:"totp_secret,omitempty"`
	Groups       []string `json:"groups,omitempty"`
	Disabled     bool     `json:"disabled,omitempty"`
}

// Network é um objeto de IP (De onde): uma ou mais faixas.
type Network struct {
	Name  string   `json:"name"`
	CIDRs []string `json:"cidrs"`
}

// Profile é um perfil de comandos (O que pode fazer).
type Profile struct {
	Name      string        `json:"name"`
	PrivLevel int           `json:"priv_level"`
	Commands  CommandPolicy `json:"commands"`
}

// CommandPolicy controla a autorização comando a comando.
//
// Padrões usam "*" como curinga e não diferenciam maiúsculas. Um padrão terminado em " *"
// também aceita o comando sem argumentos ("display *" aceita "display" e "display interface").
// Deny é avaliado antes de Allow. Sem correspondência vale Default; se Default estiver vazio,
// vale "deny" quando há lista Allow e "allow" caso contrário.
type CommandPolicy struct {
	Default Action   `json:"default,omitempty"`
	Allow   []string `json:"allow,omitempty"`
	Deny    []string `json:"deny,omitempty"`
}

// Schedule é um objeto de horário (Quando).
type Schedule struct {
	Name    string   `json:"name"`
	Windows []Window `json:"windows"`
}

// Window é uma janela semanal. Days: 1 = segunda … 7 = domingo. Start e End em "HH:MM".
// Se End ≤ Start, a janela atravessa a meia-noite (ex.: plantão 18:00–08:00) e o dia é o do início.
type Window struct {
	Days  []int  `json:"days"`
	Start string `json:"start"`
	End   string `json:"end"`
}

// Rule é uma regra AAA.
//
// Referências:
//   - Who:   "all" | "none" | "user:<usuario@dominio>" | "group:<Nome@dominio>"
//   - Where: "all" | "none" | "device:<nome>" | "group:<grupo>" | "vendor:<fabricante>"
//   - From:  "all" | "none" | "net:<objeto>" | "cidr:<faixa>"
//   - What:  "none" | "profile:<perfil>"  (obrigatório só em regras de permitir)
//   - When:  "always" | "never" | "schedule:<horário>"  (vazio = sempre)
//   - MFA:   "totp" | "device" | "none"  (vazio = device)
type Rule struct {
	ID     string   `json:"id,omitempty"`
	Name   string   `json:"name"`
	Scope  string   `json:"scope"`
	Action Action   `json:"action"`
	Who    []string `json:"who"`
	Where  []string `json:"where"`
	From   []string `json:"from"`
	What   string   `json:"what,omitempty"`
	When   []string `json:"when,omitempty"`
	MFA    string   `json:"mfa,omitempty"`
}

// Missing devolve os campos obrigatórios vazios (em português, para a tela e o simulador).
func (r *Rule) Missing() []string {
	var m []string
	if len(r.Who) == 0 {
		m = append(m, "Quem")
	}
	if len(r.Where) == 0 {
		m = append(m, "Onde")
	}
	if len(r.From) == 0 {
		m = append(m, "De onde")
	}
	if r.Action == Allow && r.What == "" {
		m = append(m, "O que")
	}
	return m
}

// Parse lê uma política JSON, recusando campos desconhecidos.
func Parse(r io.Reader) (*Policy, error) {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	var p Policy
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("política: JSON inválido: %w", err)
	}
	return &p, nil
}

// Load lê e compila a política do arquivo path.
func Load(path string) (*Engine, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("política: %w", err)
	}
	p, err := Parse(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	return Compile(p)
}
