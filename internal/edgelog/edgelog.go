// Package edgelog grava os eventos de AAA do Edge (autenticação, autorização e accounting)
// em JSON Lines. O arquivo funciona como fila local: quando a sincronização com a nuvem estiver
// pronta (dia 7), os eventos são enviados a partir dele, sem perda se o Edge estiver offline.
package edgelog

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// Event é um registro de auditoria do Edge.
type Event struct {
	Time     time.Time `json:"time"`
	Kind     string    `json:"kind"` // authen | author | acct
	Customer string    `json:"customer"`
	Policy   int64     `json:"policy_version"`
	Device   string    `json:"device,omitempty"`
	DeviceIP string    `json:"device_ip"`
	User     string    `json:"user,omitempty"`
	RemAddr  string    `json:"rem_addr,omitempty"`
	Port     string    `json:"port,omitempty"`
	Result   string    `json:"result"` // pass | fail | error | start | stop | watchdog
	Reason   string    `json:"reason,omitempty"`
	Rule     string    `json:"rule,omitempty"`
	MFA      string    `json:"mfa,omitempty"` // none | totp | trusted
	Priv     int       `json:"priv_level,omitempty"`
	Command  string    `json:"command,omitempty"` // já mascarado
	TaskID   string    `json:"task_id,omitempty"`
}

// Logger recebe eventos.
type Logger interface {
	Log(Event)
}

// FileLogger grava eventos num arquivo JSONL com fsync a cada evento: um registro de comando
// confirmado ao equipamento não pode se perder numa queda de energia.
type FileLogger struct {
	mu sync.Mutex
	f  *os.File
}

// OpenFile abre (ou cria) o arquivo de eventos para acréscimo.
func OpenFile(path string) (*FileLogger, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	return &FileLogger{f: f}, nil
}

// Log implementa Logger.
func (l *FileLogger) Log(e Event) {
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	b = append(b, '\n')
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, err := l.f.Write(b); err == nil {
		_ = l.f.Sync()
	}
}

// Close fecha o arquivo.
func (l *FileLogger) Close() error { return l.f.Close() }

// MemoryLogger guarda eventos em memória (testes).
type MemoryLogger struct {
	mu     sync.Mutex
	events []Event
}

// Log implementa Logger.
func (m *MemoryLogger) Log(e Event) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, e)
}

// Events devolve uma cópia dos eventos registrados.
func (m *MemoryLogger) Events() []Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Event(nil), m.events...)
}
