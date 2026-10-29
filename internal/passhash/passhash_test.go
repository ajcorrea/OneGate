package passhash

import (
	"strings"
	"testing"
)

func TestHashAndVerify(t *testing.T) {
	h, err := Hash("s3nh@-forte")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Fatalf("formato inesperado: %s", h)
	}
	ok, err := Verify("s3nh@-forte", h)
	if err != nil || !ok {
		t.Fatalf("senha correta rejeitada: ok=%v err=%v", ok, err)
	}
	ok, err = Verify("s3nh@-errada", h)
	if err != nil || ok {
		t.Fatalf("senha errada aceita: ok=%v err=%v", ok, err)
	}
}

func TestSaltsDiffer(t *testing.T) {
	a, _ := Hash("igual")
	b, _ := Hash("igual")
	if a == b {
		t.Fatal("dois hashes da mesma senha não podem ser iguais")
	}
}

func TestRejectsMalformedAndAbusiveHashes(t *testing.T) {
	bad := []string{
		"",
		"texto-puro",
		"$argon2i$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
		"$argon2id$v=16$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
		"$argon2id$v=19$m=99999999,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
		"$argon2id$v=19$m=19456,t=2,p=1$!!!$aGFzaGhhc2hoYXNoaGFzaA",
	}
	for _, h := range bad {
		if Valid(h) {
			t.Errorf("hash deveria ser inválido: %q", h)
		}
		if ok, err := Verify("x", h); ok || err == nil {
			t.Errorf("Verify deveria falhar para %q", h)
		}
	}
}
