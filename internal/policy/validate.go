package policy

import (
	"errors"
	"fmt"
)

// ValidateProfile confere um perfil de comandos isolado (usado pela nuvem ao salvar o objeto).
func ValidateProfile(p Profile) error {
	if p.PrivLevel < 0 || p.PrivLevel > 15 {
		return errors.New("nível de privilégio entre 0 e 15")
	}
	switch p.Commands.Default {
	case "", Allow, Deny:
	default:
		return errors.New("padrão dos comandos deve ser allow ou deny")
	}
	if _, err := compileCommands(p.Commands); err != nil {
		return fmt.Errorf("padrão de comando inválido: %w", err)
	}
	return nil
}

// ValidateSchedule confere um horário isolado.
func ValidateSchedule(s Schedule) error {
	if len(s.Windows) == 0 {
		return errors.New("informe pelo menos uma janela")
	}
	for i, w := range s.Windows {
		if _, err := compileWindow(w); err != nil {
			return fmt.Errorf("janela %d: %w", i+1, err)
		}
	}
	return nil
}

// ValidateCIDR confere um IP ou faixa ("10.0.0.0/24", "10.0.0.1", IPv6).
func ValidateCIDR(s string) error {
	if _, err := parsePrefix(s); err != nil {
		return fmt.Errorf("faixa inválida %q", s)
	}
	return nil
}

// NormalizeCIDR devolve a faixa na forma canônica (IP solto vira /32 ou /128).
func NormalizeCIDR(s string) (string, error) {
	p, err := parsePrefix(s)
	if err != nil {
		return "", fmt.Errorf("faixa inválida %q", s)
	}
	return p.String(), nil
}

// ValidTimezone confere o nome do fuso (ex.: America/Sao_Paulo).
func ValidTimezone(tz string) bool {
	_, err := loadLocation(tz)
	return err == nil
}
