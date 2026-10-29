package secretbox

import (
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func newKey() string {
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	return base64.StdEncoding.EncodeToString(k)
}

func TestSealOpen(t *testing.T) {
	b, err := New(newKey())
	if err != nil {
		t.Fatal(err)
	}
	s, err := b.Seal("JBSWY3DPEHPK3PXP", "user:1")
	if err != nil {
		t.Fatal(err)
	}
	got, err := b.Open(s, "user:1")
	if err != nil || got != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("got %q err %v", got, err)
	}
	if _, err := b.Open(s, "user:2"); err == nil {
		t.Fatal("contexto diferente não pode decifrar")
	}
	other, _ := New(newKey())
	if _, err := other.Open(s, "user:1"); err == nil {
		t.Fatal("chave diferente não pode decifrar")
	}
}

func TestRejectsBadKey(t *testing.T) {
	if _, err := New("curta"); err == nil {
		t.Fatal("chave inválida aceita")
	}
}
