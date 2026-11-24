package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vivekjami/tripwire/internal/config"
)

type signer struct {
	kid string
	alg string
	k   crypto.Signer
}

func enc(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func newEd(kid string) signer {
	_, k, _ := ed25519.GenerateKey(rand.Reader)
	return signer{kid, "EdDSA", k}
}
func newEC(kid string) signer {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return signer{kid, "ES256", k}
}
func newRSA(kid string, bits int) signer {
	k, _ := rsa.GenerateKey(rand.Reader, bits)
	return signer{kid, "RS256", k}
}

func (s signer) jwk() map[string]any {
	switch k := s.k.(type) {
	case ed25519.PrivateKey:
		return map[string]any{"kty": "OKP", "crv": "Ed25519", "kid": s.kid, "x": enc(k.Public().(ed25519.PublicKey))}
	case *ecdsa.PrivateKey:
		return map[string]any{"kty": "EC", "crv": "P-256", "kid": s.kid, "x": enc(k.X.FillBytes(make([]byte, 32))), "y": enc(k.Y.FillBytes(make([]byte, 32)))}
	case *rsa.PrivateKey:
		return map[string]any{"kty": "RSA", "kid": s.kid, "n": enc(k.N.Bytes()), "e": enc(big.NewInt(int64(k.E)).Bytes())}
	}
	panic("key type")
}

func jwksDoc(ss ...signer) []byte {
	keys := []any{}
	for _, s := range ss {
		keys = append(keys, s.jwk())
	}
	b, _ := json.Marshal(map[string]any{"keys": keys})
	return b
}

func (s signer) sign(hdrOverride map[string]any, claims map[string]any) string {
	h := map[string]any{"alg": s.alg, "kid": s.kid, "typ": "JWT"}
	for k, v := range hdrOverride {
		if v == nil {
			delete(h, k)
		} else {
			h[k] = v
		}
	}
	hb, _ := json.Marshal(h)
	pb, _ := json.Marshal(claims)
	return signRaw(s, enc(hb)+"."+enc(pb))
}

func signRaw(s signer, signing string) string {
	var sig []byte
	switch s.alg {
	case "EdDSA":
		sig, _ = s.k.Sign(nil, []byte(signing), crypto.Hash(0))
	case "ES256":
		d := sha256.Sum256([]byte(signing))
		r, ss, _ := ecdsa.Sign(rand.Reader, s.k.(*ecdsa.PrivateKey), d[:])
		sig = append(r.FillBytes(make([]byte, 32)), ss.FillBytes(make([]byte, 32))...)
	case "RS256":
		d := sha256.Sum256([]byte(signing))
		sig, _ = s.k.Sign(rand.Reader, d[:], crypto.SHA256)
	}
	return signing + "." + enc(sig)
}

var t0 = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

func claims(over map[string]any) map[string]any {
	c := map[string]any{"iss": "https://idp.test", "aud": "tripwire", "sub": "billing-bot", "exp": t0.Add(10 * time.Minute).Unix(), "nbf": t0.Add(-time.Minute).Unix()}
	for k, v := range over {
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
	}
	return c
}

type rig struct {
	v     *JWTVerifier
	doc   atomic.Value // []byte
	fails atomic.Bool
	calls atomic.Int64
	clock atomic.Int64 // unix nanos
}

func newVerifier(t *testing.T, algs []string, ss ...signer) *rig {
	r := &rig{}
	r.doc.Store(jwksDoc(ss...))
	r.clock.Store(t0.UnixNano())
	c := config.JWT{Issuer: "https://idp.test", Audience: "tripwire", Algorithms: algs, JWKSFile: "unused",
		Refresh: time.Minute, StaleMax: 10 * time.Minute, MinRefresh: 5 * time.Second}
	v := NewJWTVerifier(c, "t")
	now := func() time.Time { return time.Unix(0, r.clock.Load()) }
	v.now, v.jwks.now = now, now
	v.jwks.fetch = func(context.Context) ([]byte, error) {
		r.calls.Add(1)
		if r.fails.Load() {
			return nil, errors.New("idp down")
		}
		return r.doc.Load().([]byte), nil
	}
	r.v = v
	return r
}

func (r *rig) verify(tok string) (string, error) { return r.v.Verify(context.Background(), tok) }
func (r *rig) advance(d time.Duration)           { r.clock.Add(int64(d)) }

func TestJWTValidAllAlgorithms(t *testing.T) {
	for _, s := range []signer{newEd("e1"), newEC("c1"), newRSA("r1", 2048)} {
		r := newVerifier(t, []string{"EdDSA", "ES256", "RS256"}, s)
		agent, err := r.verify(s.sign(nil, claims(nil)))
		if err != nil || agent != "billing-bot" {
			t.Errorf("%s: %q %v", s.alg, agent, err)
		}
	}
}

func TestJWTAttacksAndClaimFailures(t *testing.T) {
	ed, rs := newEd("e1"), newRSA("r1", 2048)
	r := newVerifier(t, []string{"EdDSA", "RS256"}, ed, rs)
	good := ed.sign(nil, claims(nil))
	if _, err := r.verify(good); err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(good, ".")
	hmacTok := func(key []byte) string {
		h, _ := json.Marshal(map[string]any{"alg": "HS256", "kid": "r1", "typ": "JWT"})
		p, _ := json.Marshal(claims(nil))
		signing := enc(h) + "." + enc(p)
		m := hmac.New(sha256.New, key)
		m.Write([]byte(signing))
		return signing + "." + enc(m.Sum(nil))
	}
	rsaPubDER := rs.k.(*rsa.PrivateKey).N.Bytes()
	noneH, _ := json.Marshal(map[string]any{"alg": "none", "kid": "e1"})
	noneP, _ := json.Marshal(claims(nil))
	cases := map[string]string{
		"alg none":                                enc(noneH) + "." + enc(noneP) + ".",
		"alg none with garbage sig":               enc(noneH) + "." + enc(noneP) + ".AAAA",
		"HS256 using RSA modulus (alg confusion)": hmacTok(rsaPubDER),
		"HS256 using the kid string":              hmacTok([]byte("r1")),
		"header says RS256, key is Ed25519":       signRaw(signer{"e1", "RS256", rs.k}, enc([]byte(`{"alg":"RS256","kid":"e1"}`))+"."+enc(noneP)),
		"header says EdDSA, key is RSA":           signRaw(signer{"r1", "EdDSA", ed.k}, enc([]byte(`{"alg":"EdDSA","kid":"r1"}`))+"."+enc(noneP)),
		"tampered payload":                        parts[0] + "." + enc([]byte(`{"iss":"https://idp.test","aud":"tripwire","sub":"admin","exp":99999999999}`)) + "." + parts[2],
		"signature stripped":                      parts[0] + "." + parts[1] + ".",
		"two-part token":                          parts[0] + "." + parts[1],
		"four-part token":                         good + ".x",
		"unknown kid":                             newEd("zzz").sign(nil, claims(nil)),
		"no kid":                                  ed.sign(map[string]any{"kid": nil}, claims(nil)),
		"expired":                                 ed.sign(nil, claims(map[string]any{"exp": t0.Add(-time.Hour).Unix()})),
		"no exp":                                  ed.sign(nil, claims(map[string]any{"exp": nil})),
		"not yet valid":                           ed.sign(nil, claims(map[string]any{"nbf": t0.Add(time.Hour).Unix()})),
		"wrong audience":                          ed.sign(nil, claims(map[string]any{"aud": "someone-else"})),
		"audience array without ours":             ed.sign(nil, claims(map[string]any{"aud": []string{"a", "b"}})),
		"wrong issuer":                            ed.sign(nil, claims(map[string]any{"iss": "https://evil"})),
		"no subject":                              ed.sign(nil, claims(map[string]any{"sub": nil})),
		"non-string subject":                      ed.sign(nil, claims(map[string]any{"sub": 7})),
		"duplicate key in header":                 signRaw(ed, enc([]byte(`{"alg":"EdDSA","kid":"e1","alg":"EdDSA"}`))+"."+enc(noneP)),
		"duplicate key in payload":                signRaw(ed, parts[0]+"."+enc([]byte(`{"iss":"https://idp.test","aud":"tripwire","sub":"a","sub":"b","exp":99999999999}`))),
		"huge token":                              parts[0] + "." + enc(make([]byte, 20000)) + "." + parts[2],
		"garbage":                                 "not.a.jwt",
		"empty":                                   "",
	}
	for name, tok := range cases {
		if agent, err := r.verify(tok); err == nil {
			t.Errorf("%s: ACCEPTED as %q", name, agent)
		} else if !errors.Is(err, ErrJWT) || err.Error() != "auth: invalid token" {
			t.Errorf("%s: error leaks detail: %v", name, err)
		}
	}
	// within leeway: expired 10s ago is still accepted; 60s ago is not
	if _, err := r.verify(ed.sign(nil, claims(map[string]any{"exp": t0.Add(-10 * time.Second).Unix()}))); err != nil {
		t.Errorf("exp inside leeway rejected: %v", err)
	}
	if _, err := r.verify(ed.sign(nil, claims(map[string]any{"aud": []string{"x", "tripwire"}}))); err != nil {
		t.Errorf("audience array containing ours rejected: %v", err)
	}
}

func TestJWTAlgorithmAllowListIsConfiguration(t *testing.T) {
	ed := newEd("e1")
	r := newVerifier(t, []string{"RS256"}, ed) // EdDSA key present, but EdDSA not allowed
	if _, err := r.verify(ed.sign(nil, claims(nil))); err == nil {
		t.Fatal("an algorithm outside the configured allow-list was accepted")
	}
}

func TestJWKSRejectsWeakAndMalformedKeys(t *testing.T) {
	weak := newRSA("weak", 1024)
	ed := newEd("ok")
	r := newVerifier(t, []string{"RS256", "EdDSA"}, weak, ed)
	if _, err := r.verify(weak.sign(nil, claims(nil))); err == nil {
		t.Fatal("a 1024-bit RSA key was accepted")
	}
	if _, err := r.verify(ed.sign(nil, claims(nil))); err != nil {
		t.Fatalf("the usable key must still work: %v", err)
	}
	if _, err := parseJWKS([]byte(`{"keys":[{"kty":"EC","crv":"P-256","kid":"bad","x":"AA","y":"AA"}]}`)); err == nil {
		t.Fatal("an off-curve EC point was accepted")
	}
	if _, err := parseJWKS([]byte(`{"keys":[],"keys":[]}`)); err == nil {
		t.Fatal("duplicate keys in JWKS accepted")
	}
}

func TestJWKSRotationOverlapAndRefreshOnUnknownKid(t *testing.T) {
	oldK, newK := newEd("old"), newEd("new")
	r := newVerifier(t, []string{"EdDSA"}, oldK)
	if _, err := r.verify(oldK.sign(nil, claims(nil))); err != nil {
		t.Fatal(err)
	}
	// IdP publishes both keys (overlap). A token with the new kid triggers a refresh (min_refresh elapsed).
	r.doc.Store(jwksDoc(oldK, newK))
	r.advance(6 * time.Second)
	if _, err := r.verify(newK.sign(nil, claims(nil))); err != nil {
		t.Fatalf("new key not picked up on an unknown kid: %v", err)
	}
	if _, err := r.verify(oldK.sign(nil, claims(map[string]any{"jti": "2"}))); err != nil {
		t.Fatalf("old key must work during the overlap: %v", err)
	}
	// IdP retires the old key; after the next scheduled refresh it stops verifying
	r.doc.Store(jwksDoc(newK))
	r.advance(2 * time.Minute)
	if _, err := r.verify(oldK.sign(nil, claims(map[string]any{"jti": "3", "exp": t0.Add(time.Hour).Unix()}))); err == nil {
		t.Fatal("retired key still verifies after refresh")
	}
	// a flood of unknown kids must not hammer the IdP
	before := r.calls.Load()
	for i := 0; i < 200; i++ {
		_, _ = r.verify(newEd(fmt.Sprintf("x%d", i)).sign(nil, claims(nil)))
	}
	if n := r.calls.Load() - before; n > 2 {
		t.Fatalf("%d JWKS fetches for 200 unknown-kid tokens (min_refresh must rate-limit)", n)
	}
}

func TestJWKSStaleIfError(t *testing.T) {
	k := newEd("k1")
	r := newVerifier(t, []string{"EdDSA"}, k)
	if _, err := r.verify(k.sign(nil, claims(nil))); err != nil {
		t.Fatal(err)
	}
	r.fails.Store(true)
	r.advance(3 * time.Minute) // past refresh, within stale_max: keep serving the cached keys
	tok := k.sign(nil, claims(map[string]any{"jti": "a", "exp": t0.Add(time.Hour).Unix()}))
	if _, err := r.verify(tok); err != nil {
		t.Fatalf("stale-if-error: cached keys must keep working while the IdP is down: %v", err)
	}
	r.advance(20 * time.Minute) // beyond stale_max: stop trusting a key set we cannot refresh
	tok2 := k.sign(nil, claims(map[string]any{"jti": "b", "exp": t0.Add(2 * time.Hour).Unix()}))
	if _, err := r.verify(tok2); err == nil {
		t.Fatal("keys older than stale_max were still trusted")
	}
	r.fails.Store(false) // IdP recovers
	r.advance(10 * time.Second)
	if _, err := r.verify(tok2); err != nil {
		t.Fatalf("did not recover after the IdP came back: %v", err)
	}
}

func TestJWTVerificationCache(t *testing.T) {
	k := newEd("k1")
	r := newVerifier(t, []string{"EdDSA"}, k)
	tok := k.sign(nil, claims(nil))
	for i := 0; i < 50; i++ {
		if _, err := r.verify(tok); err != nil {
			t.Fatal(err)
		}
	}
	if h, m := r.v.Stats(); h != 49 || m != 1 {
		t.Fatalf("cache hits=%d misses=%d, want 49/1", h, m)
	}
	// the cache never outlives exp (+0): move past exp+leeway and the same token fails
	r.advance(10*time.Minute + time.Minute)
	if _, err := r.verify(tok); err == nil {
		t.Fatal("cached token accepted after expiry")
	}
	// a long-lived token is re-verified within 5 minutes so key revocation takes effect
	long := k.sign(nil, claims(map[string]any{"exp": t0.Add(24 * time.Hour).Unix(), "jti": "L"}))
	r.advance(0)
	_, _ = r.verify(long)
	r.doc.Store(jwksDoc(newEd("other")))
	r.advance(6 * time.Minute)
	if _, err := r.verify(long); err == nil {
		t.Fatal("a revoked key's long-lived token survived the 5-minute re-verification bound")
	}
}

func TestJWTMaxLifetime(t *testing.T) {
	k := newEd("k1")
	r := newVerifier(t, []string{"EdDSA"}, k)
	r.v.cfg.MaxLifetime = 15 * time.Minute
	if _, err := r.verify(k.sign(nil, claims(map[string]any{"exp": t0.Add(10 * time.Minute).Unix()}))); err != nil {
		t.Fatal(err)
	}
	if _, err := r.verify(k.sign(nil, claims(map[string]any{"exp": t0.Add(24 * time.Hour).Unix(), "jti": "x"}))); err == nil {
		t.Fatal("token valid for 24h accepted despite max_lifetime")
	}
}

// Statistical uniformity: failures must not reveal, through timing, how far a
// token got. Each failure class is timed many times; the medians must be within
// a small factor of each other (the dummy verification equalizes the early exits).
func TestJWTFailureTimingIsUniform(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test")
	}
	k := newEd("k1")
	r := newVerifier(t, []string{"EdDSA"}, k)
	good := k.sign(nil, claims(nil))
	parts := strings.Split(good, ".")
	classes := map[string]func(i int) string{
		"malformed":   func(i int) string { return fmt.Sprintf("garbage-%d", i) },
		"bad base64":  func(i int) string { return fmt.Sprintf("!!.!!.!!%d", i) },
		"alg none":    func(i int) string { return enc([]byte(`{"alg":"none"}`)) + "." + parts[1] + "." },
		"unknown kid": func(i int) string { return newEd("zz").sign(nil, claims(map[string]any{"jti": i})) },
		"bad signature": func(i int) string {
			return parts[0] + "." + enc([]byte(fmt.Sprintf(`{"exp":%d}`, i+1))) + "." + parts[2]
		},
		"expired (valid sig)": func(i int) string {
			return k.sign(nil, claims(map[string]any{"exp": t0.Add(-time.Hour).Unix(), "jti": i}))
		},
	}
	// make the unknown-kid class not trigger JWKS fetch work: pre-fill the attempt time
	_, _ = r.verify(good)
	med := map[string]time.Duration{}
	toks := map[string][]string{}
	for name, gen := range classes {
		for i := 0; i < 400; i++ {
			toks[name] = append(toks[name], gen(i))
		}
	}
	for round := 0; round < 3; round++ { // warm up and interleave classes to share noise
		for name, ts := range toks {
			d := make([]time.Duration, 0, len(ts))
			for _, tok := range ts {
				st := time.Now()
				_, _ = r.verify(tok)
				d = append(d, time.Since(st))
			}
			sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
			med[name] = d[len(d)/2]
		}
	}
	var lo, hi time.Duration = 1 << 62, 0
	for _, m := range med {
		if m < lo {
			lo = m
		}
		if m > hi {
			hi = m
		}
	}
	t.Logf("median failure latency per class: %v", med)
	if hi > 4*lo {
		t.Fatalf("failure timing differs by %.1fx between classes (medians %v): timing reveals how far a token got", float64(hi)/float64(lo), med)
	}
}

func TestRegistryBearerRouting(t *testing.T) {
	k := newEd("k1")
	cfg := config.Defaults()
	cfg.Agents = []config.Agent{{ID: "billing-bot", Tenant: "t"}}
	cfg.Auth.JWT = config.JWT{Issuer: "https://idp.test", Audience: "tripwire", Algorithms: []string{"EdDSA"}, JWKSFile: "x"}
	reg, err := Build(&cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	reg.jwt.now, reg.jwt.jwks.now = func() time.Time { return now }, func() time.Time { return now }
	reg.jwt.jwks.fetch = func(context.Context) ([]byte, error) { return jwksDoc(k), nil }
	tok := k.sign(nil, claims(map[string]any{"exp": now.Add(time.Minute).Unix(), "nbf": now.Add(-time.Minute).Unix()}))
	if a, ok := reg.AuthenticateBearer(context.Background(), tok, now); !ok || a.ID != "billing-bot" {
		t.Fatal("JWT not accepted through the registry")
	}
	// a token naming an agent that is not in the registry is rejected (identity, not scope)
	tok2 := k.sign(nil, claims(map[string]any{"sub": "ghost", "exp": now.Add(time.Minute).Unix(), "nbf": now.Add(-time.Minute).Unix()}))
	if _, ok := reg.AuthenticateBearer(context.Background(), tok2, now); ok {
		t.Fatal("unknown agent accepted")
	}
	if _, ok := reg.AuthenticateBearer(context.Background(), "something-else", now); ok {
		t.Fatal("garbage accepted")
	}
	// reload with an unchanged JWT config keeps the verifier (and its caches)
	reg2, _ := Build(&cfg, nil, reg)
	if reg2.JWT() != reg.JWT() {
		t.Fatal("JWKS and token caches were discarded by a no-op reload")
	}
}
