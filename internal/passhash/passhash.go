// Package passhash gera e verifica hashes de senha Argon2id no formato PHC:
//
//	$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>
//
// Os parâmetros padrão seguem a recomendação mínima da OWASP para Argon2id.
package passhash

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Params define o custo do Argon2id.
type Params struct {
	Memory  uint32 // KiB
	Time    uint32
	Threads uint8
	SaltLen uint32
	KeyLen  uint32
}

// Default é o custo usado para novos hashes.
var Default = Params{Memory: 19456, Time: 2, Threads: 1, SaltLen: 16, KeyLen: 32}

// Limites aceitos ao verificar, para que um hash adulterado não consuma memória sem controle.
const (
	maxMemory  = 256 * 1024
	maxTime    = 10
	maxThreads = 16
)

var (
	// ErrInvalidHash indica um hash fora do formato esperado.
	ErrInvalidHash = errors.New("passhash: hash inválido")
	b64            = base64.RawStdEncoding
)

// Hash gera o hash Argon2id de password com os parâmetros padrão.
func Hash(password string) (string, error) {
	return HashWith(password, Default)
}

// HashWith gera o hash Argon2id de password com os parâmetros informados.
func HashWith(password string, p Params) (string, error) {
	salt := make([]byte, p.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("passhash: gerar salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, p.Time, p.Memory, p.Threads, p.KeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.Memory, p.Time, p.Threads, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// Verify informa se password corresponde ao hash encoded.
func Verify(password, encoded string) (bool, error) {
	p, salt, key, err := decode(encoded)
	if err != nil {
		return false, err
	}
	got := argon2.IDKey([]byte(password), salt, p.Time, p.Memory, p.Threads, uint32(len(key)))
	return subtle.ConstantTimeCompare(got, key) == 1, nil
}

// dummy é usado por VerifyDummy para gastar o mesmo tempo quando o usuário não existe.
var dummy, _ = Hash("onegate-dummy-password")

// VerifyDummy executa uma verificação descartável. Chame quando o usuário não existir,
// para que o tempo de resposta não revele quais usuários existem.
func VerifyDummy(password string) {
	_, _ = Verify(password, dummy)
}

func decode(encoded string) (Params, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	// "", "argon2id", "v=19", "m=..,t=..,p=..", salt, hash
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return Params{}, nil, nil, ErrInvalidHash
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return Params{}, nil, nil, ErrInvalidHash
	}
	var p Params
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Time, &p.Threads); err != nil {
		return Params{}, nil, nil, ErrInvalidHash
	}
	if p.Memory == 0 || p.Memory > maxMemory || p.Time == 0 || p.Time > maxTime || p.Threads == 0 || p.Threads > maxThreads {
		return Params{}, nil, nil, ErrInvalidHash
	}
	salt, err := b64.DecodeString(parts[4])
	if err != nil || len(salt) < 8 {
		return Params{}, nil, nil, ErrInvalidHash
	}
	key, err := b64.DecodeString(parts[5])
	if err != nil || len(key) < 16 || len(key) > 64 {
		return Params{}, nil, nil, ErrInvalidHash
	}
	return p, salt, key, nil
}

// Valid informa se encoded está num formato aceito.
func Valid(encoded string) bool {
	_, _, _, err := decode(encoded)
	return err == nil
}
