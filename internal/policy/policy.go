// Package policy define a política de acesso que a nuvem publica para os Edges de um cliente
// e o motor que decide autenticação, MFA e autorização de comandos.
//
// A política é um documento único por cliente. O Edge nunca a edita: só recebe versões novas.
package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// MFAMode é a configuração de MFA de um nível (cliente, grupo de equipamentos ou equipamento).
type MFAMode string

const (
	// MFAInherit segue o nível acima (válido para grupo e equipamento).
	MFAInherit MFAMode = "inherit"
	// MFAOff dispensa o MFA (ainda pode ser exigido por regra de grupo de técnicos).
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

// Policy é o documento completo de um cliente.
type Policy struct {
	Version      int64         `json:"version"`
	Customer     Customer      `json:"customer"`
	DeviceGroups []DeviceGroup `json:"device_groups"`
	Devices      []Device      `json:"devices"`
	UserGroups   []UserGroup   `json:"user_groups"`
	Users        []User        `json:"users"`
	Rules        []Rule        `json:"rules"`
}

// Customer guarda os padrões do cliente.
type Customer struct {
	Code string `json:"code"`
	Name string `json:"name"`
	// MFA padrão do cliente: "off" ou "totp".
	MFA MFAMode `json:"mfa"`
	// Janela de confiança padrão, em segundos. 0 = sempre pedir o código.
	TrustWindowSeconds int `json:"trust_window_seconds"`
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
	Address string  `json:"address"`
	Group   string  `json:"group"`
	Vendor  string  `json:"vendor,omitempty"`
	MFA     MFAMode `json:"mfa"`
	// CodeEntry padrão: prompt.
	CodeEntry          CodeEntry `json:"code_entry,omitempty"`
	TrustWindowSeconds *int      `json:"trust_window_seconds,omitempty"`
	// Secret é a chave compartilhada TACACS+/RADIUS deste equipamento.
	Secret string `json:"secret"`
}

// UserGroup agrupa técnicos (ex.: NOC, Suporte N1, Terceirizados).
type UserGroup struct {
	Name string `json:"name"`
	// RequireMFA exige TOTP mesmo em equipamentos sem MFA. Só endurece, nunca afrouxa.
	RequireMFA         bool `json:"require_mfa"`
	TrustWindowSeconds *int `json:"trust_window_seconds,omitempty"`
}

// User é um técnico ou conta de serviço.
type User struct {
	Username     string   `json:"username"`
	Name         string   `json:"name,omitempty"`
	PasswordHash string   `json:"password_hash"`
	TOTPSecret   string   `json:"totp_secret,omitempty"`
	Groups       []string `json:"groups"`
	Disabled     bool     `json:"disabled,omitempty"`
	// Service marca contas de serviço (backup, monitoramento): nunca usam MFA e
	// só são aceitas a partir de AllowedSources.
	Service        bool     `json:"service,omitempty"`
	AllowedSources []string `json:"allowed_sources,omitempty"`
}

// Rule é uma regra da política. A primeira que corresponder decide.
type Rule struct {
	Name         string        `json:"name"`
	UserGroups   []string      `json:"user_groups,omitempty"`
	DeviceGroups []string      `json:"device_groups,omitempty"`
	Action       Action        `json:"action"`
	PrivLevel    int           `json:"priv_level,omitempty"`
	Commands     CommandPolicy `json:"commands"`
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
