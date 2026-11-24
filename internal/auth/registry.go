package auth

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/vivekjami/tripwire/internal/config"
)

// Agent is the compiled, immutable view of one agent plus its live limiters.
type Agent struct {
	ID      string
	Tenant  string
	Models  []Glob
	MaxBody int64 // 0 = use the global body limit

	Rate    *Bucket
	Streams *Gate

	rps    float64
	burst  int
	nStrms int64
}

// ModelAllowed reports whether the agent may use model (exact-string matching).
func (a *Agent) ModelAllowed(model string) bool {
	for _, g := range a.Models {
		if g.Match(model) {
			return true
		}
	}
	return false
}

// Registry is an immutable snapshot (ARCHITECTURE §8.2). It is replaced
// wholesale; readers never lock.
type Registry struct {
	agents map[string]*Agent
	keys   *keyStore
}

// Agent returns the agent with the given id.
func (r *Registry) Agent(id string) (*Agent, bool) { a, ok := r.agents[id]; return a, ok }

// Authenticate verifies an API key and returns its agent.
func (r *Registry) Authenticate(key string, now time.Time) (*Agent, bool) {
	id, ok := r.keys.verify(key, now)
	if !ok {
		return nil, false
	}
	a, ok := r.agents[id]
	return a, ok
}

// Len is the number of agents.
func (r *Registry) Len() int { return len(r.agents) }

// Build compiles a Registry from config. prev (may be nil) lets agents whose
// limits did not change keep their live limiter state across a reload, so a
// reload does not hand every agent a fresh burst allowance.
func Build(cfg *config.Config, pepper []byte, prev *Registry) (*Registry, error) {
	if len(cfg.Auth.APIKeys) > 0 && len(pepper) < minPepper {
		return nil, fmt.Errorf("auth: pepper must be at least %d bytes", minPepper)
	}
	r := &Registry{agents: make(map[string]*Agent, len(cfg.Agents)), keys: &keyStore{pepper: pepper, byAgent: map[string][]keyEntry{}}}
	for _, ac := range cfg.Agents {
		a := &Agent{ID: ac.ID, Tenant: ac.Tenant, MaxBody: ac.Limits.MaxBody,
			rps: ac.Limits.RPS, burst: ac.Limits.Burst, nStrms: int64(ac.Limits.ConcurrentStreams)}
		for _, m := range ac.Models {
			a.Models = append(a.Models, CompileGlob(m))
		}
		a.Rate, a.Streams = NewBucket(a.rps, a.burst), NewGate(a.nStrms)
		if prev != nil {
			if old, ok := prev.agents[a.ID]; ok && old.rps == a.rps && old.burst == a.burst && old.nStrms == a.nStrms {
				a.Rate, a.Streams = old.Rate, old.Streams
			}
		}
		r.agents[a.ID] = a
	}
	for _, k := range cfg.Auth.APIKeys {
		b, err := hex.DecodeString(k.SHA256)
		if err != nil || len(b) != 32 {
			return nil, fmt.Errorf("auth: api key for %q: bad sha256", k.Agent)
		}
		e := keyEntry{notBefore: k.NotBefore, notAfter: k.NotAfter}
		copy(e.hash[:], b)
		r.keys.byAgent[k.Agent] = append(r.keys.byAgent[k.Agent], e)
	}
	return r, nil
}

// ReadPepper loads the pepper file (trailing newline trimmed).
func ReadPepper(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path) //nolint:gosec // operator-supplied secret path
	if err != nil {
		return nil, fmt.Errorf("auth: pepper: %w", err)
	}
	return []byte(strings.TrimRight(string(b), "\r\n")), nil
}

// Holder publishes the current Registry snapshot.
type Holder struct{ p atomic.Pointer[Registry] }

// Load returns the current snapshot (nil before the first Store).
func (h *Holder) Load() *Registry { return h.p.Load() }

// Store publishes a snapshot atomically.
func (h *Holder) Store(r *Registry) { h.p.Store(r) }
