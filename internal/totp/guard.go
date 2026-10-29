package totp

import (
	"sync"
	"time"
)

// ReplayGuard impede que o mesmo código seja aceito duas vezes para o mesmo usuário.
// Implementações distribuídas (os 2 Edges de um cliente) satisfazem a mesma interface.
type ReplayGuard interface {
	// Use registra o passo para o usuário. Devolve false se o passo (ou um posterior)
	// já tiver sido usado por esse usuário.
	Use(user string, step int64) bool
}

// MemoryGuard guarda em memória o último passo aceito de cada usuário.
// Aceitar só passos estritamente maiores que o último também bloqueia o reuso de um código
// antigo ainda dentro da tolerância.
type MemoryGuard struct {
	mu   sync.Mutex
	last map[string]int64
	now  func() time.Time
}

// NewMemoryGuard cria um guarda em memória.
func NewMemoryGuard() *MemoryGuard {
	return &MemoryGuard{last: make(map[string]int64), now: time.Now}
}

// Use implementa ReplayGuard.
func (g *MemoryGuard) Use(user string, step int64) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if prev, ok := g.last[user]; ok && step <= prev {
		return false
	}
	g.last[user] = step
	g.gc()
	return true
}

// gc remove entradas antigas que não podem mais colidir com códigos válidos.
func (g *MemoryGuard) gc() {
	if len(g.last) < 1024 {
		return
	}
	cutoff := Step(g.now()) - 4
	for u, s := range g.last {
		if s < cutoff {
			delete(g.last, u)
		}
	}
}
