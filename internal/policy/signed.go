package policy

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Package é a política assinada que a nuvem entrega ao Edge. A assinatura Ed25519 cobre os bytes
// exatos do campo policy, então o Edge verifica antes de interpretar o documento.
type Package struct {
	KeyID     string          `json:"key_id"`
	Signature string          `json:"signature"`
	Policy    json.RawMessage `json:"policy"`
}

// KeyID identifica uma chave pública (16 caracteres hex do SHA-256).
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// Sign gera o pacote assinado de uma política.
func Sign(p *Policy, priv ed25519.PrivateKey) ([]byte, error) {
	doc, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	pkg := Package{
		KeyID:     KeyID(priv.Public().(ed25519.PublicKey)),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, doc)),
		Policy:    doc,
	}
	// Sem indentação: reformatar o campo policy mudaria os bytes assinados.
	return json.Marshal(pkg)
}

// ParsePublicKey lê uma chave pública Ed25519 em base64.
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("chave pública inválida (esperado Ed25519 em base64)")
	}
	return ed25519.PublicKey(b), nil
}

// Verify confere a assinatura e devolve a política contida no pacote.
func Verify(data []byte, pub ed25519.PublicKey) (*Policy, error) {
	var pkg Package
	if err := json.Unmarshal(data, &pkg); err != nil || len(pkg.Policy) == 0 {
		return nil, errors.New("pacote de política inválido")
	}
	if pkg.KeyID != KeyID(pub) {
		return nil, fmt.Errorf("pacote assinado por outra chave (%s)", pkg.KeyID)
	}
	sig, err := base64.StdEncoding.DecodeString(pkg.Signature)
	if err != nil || !ed25519.Verify(pub, pkg.Policy, sig) {
		return nil, errors.New("assinatura da política não confere")
	}
	return Parse(bytes.NewReader(pkg.Policy))
}

// LoadSigned lê, verifica e compila um pacote assinado.
func LoadSigned(path string, pub ed25519.PublicKey) (*Engine, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("política: %w", err)
	}
	p, err := Verify(b, pub)
	if err != nil {
		return nil, err
	}
	return Compile(p)
}
