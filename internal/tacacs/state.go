package tacacs

import (
	"sync"
	"time"
)

// trustStore guarda as janelas de confiança abertas: depois de um TOTP válido, o mesmo técnico,
// a partir do mesmo IP, não precisa de outro código até expirar.
type trustStore struct {
	mu      sync.Mutex
	entries map[string]time.Time
}

func newTrustStore() *trustStore { return &trustStore{entries: map[string]time.Time{}} }

func (t *trustStore) key(user, src string) string { return user + "\x00" + src }

func (t *trustStore) trusted(user, src string, now time.Time) bool {
	if src == "" {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	exp, ok := t.entries[t.key(user, src)]
	return ok && now.Before(exp)
}

func (t *trustStore) grant(user, src string, until time.Time) {
	if src == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.entries[t.key(user, src)] = until
	if len(t.entries) > 4096 {
		now := time.Now()
		for k, v := range t.entries {
			if now.After(v) {
				delete(t.entries, k)
			}
		}
	}
}

// failureLimiter bloqueia temporariamente um par usuário+origem depois de várias falhas,
// para dificultar tentativa de senha e de código por força bruta.
type failureLimiter struct {
	mu       sync.Mutex
	max      int
	window   time.Duration
	failures map[string][]time.Time
}

func newFailureLimiter(max int, window time.Duration) *failureLimiter {
	return &failureLimiter{max: max, window: window, failures: map[string][]time.Time{}}
}

func (f *failureLimiter) blocked(key string, now time.Time) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.recent(key, now)) >= f.max
}

func (f *failureLimiter) fail(key string, now time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failures[key] = append(f.recent(key, now), now)
}

func (f *failureLimiter) reset(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.failures, key)
}

func (f *failureLimiter) recent(key string, now time.Time) []time.Time {
	var keep []time.Time
	for _, t := range f.failures[key] {
		if now.Sub(t) < f.window {
			keep = append(keep, t)
		}
	}
	if len(keep) == 0 {
		delete(f.failures, key)
	} else {
		f.failures[key] = keep
	}
	return keep
}
