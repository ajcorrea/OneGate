package totp

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"
)

// Vetores da RFC 6238 (SHA1, segredo "12345678901234567890"), truncados para 6 dígitos.
var rfcSecret = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))

func TestRFC6238Vectors(t *testing.T) {
	cases := []struct {
		unix int64
		want string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
	}
	for _, c := range cases {
		got, err := Code(rfcSecret, time.Unix(c.unix, 0))
		if err != nil {
			t.Fatal(err)
		}
		if got != c.want {
			t.Errorf("t=%d: got %s, want %s", c.unix, got, c.want)
		}
	}
}

func TestValidateWithSkew(t *testing.T) {
	now := time.Unix(1700000000, 0)
	prev, _ := Code(rfcSecret, now.Add(-30*time.Second))
	next, _ := Code(rfcSecret, now.Add(30*time.Second))
	old, _ := Code(rfcSecret, now.Add(-90*time.Second))

	if _, ok := Validate(rfcSecret, prev, now, DefaultSkew); !ok {
		t.Error("código do passo anterior deveria ser aceito")
	}
	if _, ok := Validate(rfcSecret, next, now, DefaultSkew); !ok {
		t.Error("código do passo seguinte deveria ser aceito")
	}
	if _, ok := Validate(rfcSecret, old, now, DefaultSkew); ok {
		t.Error("código de 90 s atrás deveria ser rejeitado")
	}
	for _, bad := range []string{"", "12345", "1234567", "abcdef"} {
		if _, ok := Validate(rfcSecret, bad, now, DefaultSkew); ok {
			t.Errorf("código %q deveria ser rejeitado", bad)
		}
	}
}

func TestNewSecretAndURI(t *testing.T) {
	s, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	if len(s) != 32 {
		t.Fatalf("segredo de 160 bits deveria ter 32 caracteres, tem %d", len(s))
	}
	if _, err := Code(s, time.Now()); err != nil {
		t.Fatal(err)
	}
	uri := ProvisioningURI("ONE GATE", "alexandre.c@NSF", s)
	if !strings.HasPrefix(uri, "otpauth://totp/ONE%20GATE:alexandre.c@NSF?") || !strings.Contains(uri, "secret="+s) {
		t.Fatalf("URI inesperada: %s", uri)
	}
}

func TestReplayGuard(t *testing.T) {
	g := NewMemoryGuard()
	if !g.Use("ana", 100) {
		t.Fatal("primeiro uso deveria passar")
	}
	if g.Use("ana", 100) {
		t.Fatal("mesmo passo não pode ser reutilizado")
	}
	if g.Use("ana", 99) {
		t.Fatal("passo anterior ao último aceito não pode ser usado")
	}
	if !g.Use("ana", 101) {
		t.Fatal("passo seguinte deveria passar")
	}
	if !g.Use("bruno", 100) {
		t.Fatal("usuários são independentes")
	}
}
