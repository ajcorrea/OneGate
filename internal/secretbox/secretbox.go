// Package secretbox cifra segredos guardados no banco (ex.: sementes TOTP) com AES-256-GCM.
// A chave mestra vem do ambiente (ONEGATE_SECRET_KEY) e, mais tarde, de um cofre (Vault/KMS).
package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
)

const prefix = "v1:"

// Box cifra e decifra valores curtos.
type Box struct {
	aead cipher.AEAD
}

// New cria um Box a partir de uma chave de 32 bytes em base64.
func New(keyB64 string) (*Box, error) {
	key, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil || len(key) != 32 {
		return nil, errors.New("secretbox: a chave precisa ter 32 bytes em base64 (gere com: openssl rand -base64 32)")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Box{aead: aead}, nil
}

// Seal cifra plaintext. context amarra o valor ao seu dono (ex.: id do usuário): um valor
// copiado para outra linha não decifra.
func (b *Box) Seal(plaintext, context string) (string, error) {
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("secretbox: nonce: %w", err)
	}
	out := b.aead.Seal(nonce, nonce, []byte(plaintext), []byte(context))
	return prefix + base64.StdEncoding.EncodeToString(out), nil
}

// Open decifra um valor gerado por Seal com o mesmo context.
func (b *Box) Open(sealed, context string) (string, error) {
	if len(sealed) < len(prefix) || sealed[:len(prefix)] != prefix {
		return "", errors.New("secretbox: formato desconhecido")
	}
	raw, err := base64.StdEncoding.DecodeString(sealed[len(prefix):])
	if err != nil || len(raw) < b.aead.NonceSize() {
		return "", errors.New("secretbox: valor corrompido")
	}
	n := b.aead.NonceSize()
	pt, err := b.aead.Open(nil, raw[:n], raw[n:], []byte(context))
	if err != nil {
		return "", errors.New("secretbox: falha ao decifrar (chave ou contexto errado)")
	}
	return string(pt), nil
}
