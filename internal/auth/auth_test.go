package auth

import (
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vivekjami/tripwire/internal/config"
)

var pepper = []byte("0123456789abcdef-pepper")

func cfgWith(t *testing.T, keys ...config.APIKey) *config.Config {
	t.Helper()
	c := config.Defaults()
	c.Agents = []config.Agent{
		{ID: "billing", Tenant: "acme", Models: []string{"gpt-4*", "o?"}, Limits: config.AgentLimits{RPS: 100, Burst: 5, ConcurrentStreams: 2}},
		{ID: "ops", Tenant: "acme"},
	}
	c.Auth.APIKeys = keys
	return &c
}

func TestKeyRoundTripAndFormat(t *testing.T) {
	key, h, err := GenerateKey("billing", pepper)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(key, "tw_billing_") || agentOf(key) != "billing" {
		t.Fatalf("format: %q", key)
	}
	reg, err := Build(cfgWith(t, config.APIKey{Agent: "billing", SHA256: h}), pepper, nil)
	if err != nil {
		t.Fatal(err)
	}
	a, ok := reg.Authenticate(key, time.Now())
	if !ok || a.ID != "billing" {
		t.Fatal("valid key rejected")
	}
	// bad variants all fail the same way
	for name, k := range map[string]string{
		"empty":       "",
		"wrong tail":  key[:len(key)-1] + "A",
		"other agent": strings.Replace(key, "billing", "ops", 1),
		"unknown":     "tw_nobody_" + strings.Repeat("a", 43),
		"no prefix":   key[3:],
		"short":       "tw_billing_abc",
	} {
		if _, ok := reg.Authenticate(k, time.Now()); ok {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestPepperMattersAndMinimum(t *testing.T) {
	if _, _, err := GenerateKey("a", []byte("short")); err == nil {
		t.Fatal("short pepper accepted")
	}
	key, h, _ := GenerateKey("billing", pepper)
	reg, _ := Build(cfgWith(t, config.APIKey{Agent: "billing", SHA256: h}), []byte("a-different-pepper-xx"), nil)
	if _, ok := reg.Authenticate(key, time.Now()); ok {
		t.Fatal("key verified under a different pepper")
	}
}

func TestRotationOverlapWindow(t *testing.T) {
	oldKey, oldH, _ := GenerateKey("billing", pepper)
	newKey, newH, _ := GenerateKey("billing", pepper)
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cutover, retire := t0.Add(24*time.Hour), t0.Add(48*time.Hour)
	reg, _ := Build(cfgWith(t,
		config.APIKey{Agent: "billing", SHA256: oldH, NotAfter: retire},
		config.APIKey{Agent: "billing", SHA256: newH, NotBefore: cutover},
	), pepper, nil)
	cases := []struct {
		at       time.Time
		old, new bool
	}{
		{t0, true, false},
		{cutover, true, true}, // overlap
		{retire.Add(-time.Second), true, true},
		{retire, false, true}, // old key retired exactly at not_after
	}
	for _, c := range cases {
		_, o := reg.Authenticate(oldKey, c.at)
		_, n := reg.Authenticate(newKey, c.at)
		if o != c.old || n != c.new {
			t.Errorf("at %v: old=%v new=%v want %v %v", c.at, o, n, c.old, c.new)
		}
	}
}

func TestZeroHashCannotAuthenticate(t *testing.T) {
	// The dummy entry used for unknown agents is all-zero; a key hashing to it
	// is infeasible, but the code path must never return success for unknown agents.
	reg, _ := Build(cfgWith(t), pepper, nil)
	if _, ok := reg.Authenticate("tw_ghost_"+strings.Repeat("A", 43), time.Now()); ok {
		t.Fatal("unknown agent authenticated")
	}
}

func TestGlobAndModels(t *testing.T) {
	g := CompileGlob("gpt-4*")
	for s, want := range map[string]bool{"gpt-4": true, "gpt-4o": true, "gpt-4o-mini": true, "gpt-3": false, " gpt-4": false, "gpt-4 ": true, "GPT-4": false} {
		if g.Match(s) != want {
			t.Errorf("gpt-4* vs %q = %v", s, !want)
		}
	}
	m := CompileGlob("a*b*c")
	for s, want := range map[string]bool{"abc": true, "aXbYc": true, "ac": false, "abcc": true, "acb": false} {
		if m.Match(s) != want {
			t.Errorf("a*b*c vs %q", s)
		}
	}
	if !CompileGlob("*").Match("") || CompileGlob("exact").Match("exactly") {
		t.Fatal("edge cases")
	}
	// '?' is NOT a wildcard: literal match only
	if CompileGlob("o?").Match("o1") {
		t.Fatal("? must be literal")
	}
	reg, _ := Build(cfgWith(t), pepper, nil)
	a, _ := reg.Agent("billing")
	if !a.ModelAllowed("gpt-4o") || a.ModelAllowed("claude") || !a.ModelAllowed("o?") {
		t.Fatal("ModelAllowed")
	}
	ops, _ := reg.Agent("ops")
	if ops.ModelAllowed("gpt-4o") {
		t.Fatal("no models listed = none allowed")
	}
}

func TestBucketBurstAndRefill(t *testing.T) {
	b := NewBucket(10, 3) // 10/s, burst 3
	now := int64(1_000_000_000)
	admitted := 0
	for i := 0; i < 10; i++ {
		if ok, _ := b.Allow(now); ok {
			admitted++
		}
	}
	if admitted != 4 { // GCRA admits burst+1 back-to-back requests
		t.Fatalf("admitted %d at one instant, want 4 (burst 3 + the first)", admitted)
	}
	if ok, retry := b.Allow(now); ok || retry <= 0 || retry > 100*time.Millisecond {
		t.Fatalf("expected a short retry-after, got ok=%v %v", ok, retry)
	}
	if ok, _ := b.Allow(now + int64(150*time.Millisecond)); !ok {
		t.Fatal("no refill after 150ms")
	}
	if ok, _ := NewBucket(0, 0).Allow(now); !ok {
		t.Fatal("rps 0 means unlimited")
	}
}

func TestBucketConcurrentRateIsBounded(t *testing.T) {
	b := NewBucket(1000, 10)
	start := time.Now()
	var admitted atomic.Int64
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Since(start) < 200*time.Millisecond {
				if ok, _ := b.Allow(time.Now().UnixNano()); ok {
					admitted.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	// 200 ms at 1000/s = 200 + burst 11: never wildly above
	if n := admitted.Load(); n > 260 || n < 150 {
		t.Fatalf("admitted %d in 200ms at 1000/s", n)
	}
}

func TestGate(t *testing.T) {
	g := NewGate(2)
	first, second, third := g.TryAcquire(), g.TryAcquire(), g.TryAcquire()
	if !first || !second || third {
		t.Fatal("cap not enforced")
	}
	g.Release()
	if !g.TryAcquire() || g.Held() != 2 {
		t.Fatal("release")
	}
	var wg sync.WaitGroup
	h := NewGate(5)
	var peak, cur atomic.Int64
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if h.TryAcquire() {
				v := cur.Add(1)
				for {
					p := peak.Load()
					if v <= p || peak.CompareAndSwap(p, v) {
						break
					}
				}
				time.Sleep(time.Millisecond)
				cur.Add(-1)
				h.Release()
			}
		}()
	}
	wg.Wait()
	if peak.Load() > 5 || h.Held() != 0 {
		t.Fatalf("peak %d held %d", peak.Load(), h.Held())
	}
}

// Reload under load: readers must always see a complete snapshot, and limiter
// state survives a reload that did not change the agent's limits.
func TestRegistryReloadUnderLoad(t *testing.T) {
	key, h, _ := GenerateKey("billing", pepper)
	c1 := cfgWith(t, config.APIKey{Agent: "billing", SHA256: h})
	r1, _ := Build(c1, pepper, nil)
	var hold Holder
	hold.Store(r1)

	stop := make(chan struct{})
	var bad atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if _, ok := hold.Load().Authenticate(key, time.Now()); !ok {
					bad.Add(1)
				}
			}
		}()
	}
	for i := 0; i < 200; i++ {
		next, err := Build(c1, pepper, hold.Load())
		if err != nil {
			t.Fatal(err)
		}
		hold.Store(next)
	}
	close(stop)
	wg.Wait()
	if bad.Load() != 0 {
		t.Fatalf("%d authentications failed during reloads", bad.Load())
	}
	a0, _ := r1.Agent("billing")
	a1, _ := hold.Load().Agent("billing")
	if a0.Rate != a1.Rate || a0.Streams != a1.Streams {
		t.Fatal("limiter state was reset by a no-op reload")
	}
	// changed limits => fresh limiters
	c2 := cfgWith(t, config.APIKey{Agent: "billing", SHA256: h})
	c2.Agents[0].Limits.RPS = 1
	r2, _ := Build(c2, pepper, hold.Load())
	if a2, _ := r2.Agent("billing"); a2.Rate == a1.Rate {
		t.Fatal("changed limits must not reuse the old limiter")
	}
}

func TestBuildRejectsBadHashAndShortPepper(t *testing.T) {
	if _, err := Build(cfgWith(t, config.APIKey{Agent: "billing", SHA256: "zz"}), pepper, nil); err == nil {
		t.Fatal("bad hash accepted")
	}
	if _, err := Build(cfgWith(t, config.APIKey{Agent: "billing", SHA256: strings.Repeat("0", 64)}), []byte("x"), nil); err == nil {
		t.Fatal("short pepper accepted")
	}
}

func BenchmarkAuthenticate(b *testing.B) {
	key, h, _ := GenerateKey("billing", pepper)
	c := config.Defaults()
	c.Agents = []config.Agent{{ID: "billing", Tenant: "t"}}
	c.Auth.APIKeys = []config.APIKey{{Agent: "billing", SHA256: h}}
	reg, _ := Build(&c, pepper, nil)
	now := time.Now()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, ok := reg.Authenticate(key, now); !ok {
			b.Fatal("rejected")
		}
	}
}
