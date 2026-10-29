// Package totp implementa códigos TOTP (RFC 6238, HMAC-SHA1, 6 dígitos, passo de 30 s),
// compatíveis com Google Authenticator, Microsoft Authenticator, Authy, Bitwarden etc.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	// Period é a duração de cada passo.
	Period = 30
	// Digits é o tamanho do código.
	Digits = 6
	// DefaultSkew aceita o passo anterior e o seguinte (±30 s) para tolerar relógios fora de sincronia.
	DefaultSkew = 1
	secretBytes = 20
)

var (
	// ErrInvalidSecret indica um segredo que não é base32 válido.
	ErrInvalidSecret = errors.New("totp: segredo inválido")
	enc              = base32.StdEncoding.WithPadding(base32.NoPadding)
)

// NewSecret gera um segredo aleatório de 160 bits em base32 (sem padding).
func NewSecret() (string, error) {
	b := make([]byte, secretBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("totp: gerar segredo: %w", err)
	}
	return enc.EncodeToString(b), nil
}

func decodeSecret(secret string) ([]byte, error) {
	s := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""))
	s = strings.TrimRight(s, "=")
	key, err := enc.DecodeString(s)
	if err != nil || len(key) < 10 {
		return nil, ErrInvalidSecret
	}
	return key, nil
}

// Step devolve o número do passo que contém t.
func Step(t time.Time) int64 {
	return t.Unix() / Period
}

// CodeAt calcula o código do passo informado.
func CodeAt(secret string, step int64) (string, error) {
	key, err := decodeSecret(secret)
	if err != nil {
		return "", err
	}
	return hotp(key, uint64(step)), nil
}

// Code calcula o código válido no instante t.
func Code(secret string, t time.Time) (string, error) {
	return CodeAt(secret, Step(t))
}

func hotp(key []byte, counter uint64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", Digits, v%1000000)
}

// Validate verifica code no instante t aceitando skew passos para cada lado.
// Em caso de sucesso devolve o passo correspondente, que deve ser registrado para impedir reuso.
func Validate(secret, code string, t time.Time, skew int) (int64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != Digits || !allDigits(code) {
		return 0, false
	}
	key, err := decodeSecret(secret)
	if err != nil {
		return 0, false
	}
	now := Step(t)
	matched, found := int64(0), 0
	for d := -int64(skew); d <= int64(skew); d++ {
		c := hotp(key, uint64(now+d))
		// Compara todos os passos, sem sair cedo, para manter tempo constante.
		if subtle.ConstantTimeCompare([]byte(c), []byte(code)) == 1 && found == 0 {
			matched, found = now+d, 1
		}
	}
	return matched, found == 1
}

func allDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// ProvisioningURI gera o otpauth:// usado no QR Code de cadastro do app autenticador.
func ProvisioningURI(issuer, account, secret string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(Digits))
	q.Set("period", fmt.Sprint(Period))
	return "otpauth://totp/" + label + "?" + q.Encode()
}
