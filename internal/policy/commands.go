package policy

import (
	"regexp"
	"strings"
)

// NormalizeCommand padroniza um comando para comparação: minúsculas e espaços simples.
func NormalizeCommand(cmd string) string {
	return strings.ToLower(strings.Join(strings.Fields(cmd), " "))
}

func compilePattern(p string) (*regexp.Regexp, error) {
	p = NormalizeCommand(p)
	optionalTail := false
	if strings.HasSuffix(p, " *") {
		optionalTail = true
		p = strings.TrimSuffix(p, " *")
	}
	parts := strings.Split(p, "*")
	for i := range parts {
		parts[i] = regexp.QuoteMeta(parts[i])
	}
	expr := "^" + strings.Join(parts, ".*")
	if optionalTail {
		expr += "( .*)?"
	}
	return regexp.Compile(expr + "$")
}

type pattern struct {
	text string
	re   *regexp.Regexp
}

type commandMatcher struct {
	def   Action
	allow []pattern
	deny  []pattern
}

func compileCommands(c CommandPolicy) (*commandMatcher, error) {
	m := &commandMatcher{def: c.Default}
	if m.def == "" {
		if len(c.Allow) > 0 {
			m.def = Deny
		} else {
			m.def = Allow
		}
	}
	for _, p := range c.Allow {
		re, err := compilePattern(p)
		if err != nil {
			return nil, err
		}
		m.allow = append(m.allow, pattern{p, re})
	}
	for _, p := range c.Deny {
		re, err := compilePattern(p)
		if err != nil {
			return nil, err
		}
		m.deny = append(m.deny, pattern{p, re})
	}
	return m, nil
}

// decide devolve se o comando é permitido e qual padrão decidiu.
func (m *commandMatcher) decide(cmd string) (bool, string) {
	n := NormalizeCommand(cmd)
	for _, p := range m.deny {
		if p.re.MatchString(n) {
			return false, "negado pelo padrão \"" + p.text + "\""
		}
	}
	for _, p := range m.allow {
		if p.re.MatchString(n) {
			return true, "permitido pelo padrão \"" + p.text + "\""
		}
	}
	if m.def == Allow {
		return true, "permitido: regra sem restrição de comandos"
	}
	return false, "negado: comando fora da lista permitida"
}

// palavras após as quais o próximo argumento é segredo e não pode ir para o log.
var secretKeywords = map[string]bool{
	"password": true, "passwd": true, "secret": true, "cipher": true, "simple": true,
	"irreversible-cipher": true, "key": true, "community": true, "shared-key": true,
	"pre-shared-key": true, "authentication-key": true, "md5": true, "auth-key": true,
}

// MaskSecrets troca por "****" os argumentos que vêm depois de palavras como
// "password", "cipher" ou "community", e senhas coladas em opções como "-pSenha".
func MaskSecrets(cmd string) string {
	f := strings.Fields(cmd)
	for i := 0; i < len(f); i++ {
		low := strings.ToLower(f[i])
		if secretKeywords[low] && i+1 < len(f) {
			nxt := strings.ToLower(f[i+1])
			// "password cipher X": mascara o valor depois do modificador.
			if (nxt == "cipher" || nxt == "simple" || nxt == "irreversible-cipher" || nxt == "0" || nxt == "7") && i+2 < len(f) {
				f[i+2] = "****"
				i += 2
				continue
			}
			f[i+1] = "****"
			i++
			continue
		}
		if strings.HasPrefix(f[i], "-p") && len(f[i]) > 2 && !strings.HasPrefix(f[i], "--") {
			f[i] = "-p****"
		}
		if strings.HasPrefix(low, "--password=") {
			f[i] = f[i][:len("--password=")] + "****"
		}
	}
	return strings.Join(f, " ")
}
