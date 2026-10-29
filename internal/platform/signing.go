package platform

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

// PolicySigningKey deriva a chave Ed25519 que assina as políticas dos Edges a partir da chave mestra
// (ONEGATE_SECRET_KEY). A chave pública vai na instalação de cada Edge.
func PolicySigningKey(masterB64 string) (ed25519.PrivateKey, error) {
	master, err := base64.StdEncoding.DecodeString(masterB64)
	if err != nil || len(master) < 32 {
		return nil, errors.New("chave mestra inválida")
	}
	m := hmac.New(sha256.New, master)
	m.Write([]byte("onegate/policy-signing/v1"))
	return ed25519.NewKeyFromSeed(m.Sum(nil)), nil
}
