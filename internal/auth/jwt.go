package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vivekjami/tripwire/internal/config"
	"github.com/vivekjami/tripwire/internal/jsonscan"
)

// JWT verification (ARCHITECTURE §8.1). Design points:
//   - the algorithm allow-list comes from configuration, never from the token;
//     "none" and every HMAC algorithm are unrepresentable, so the classic
//     alg-confusion attack (verify an RS256 token as HS256 with the public key)
//     cannot be expressed;
//   - the key chosen by `kid` must be of the type the algorithm requires;
//   - header and payload are parsed with the strict scanner (duplicate keys
//     rejected) before encoding/json is used;
//   - results are cached per token hash until exp (bounded by cache_ttl);
//   - every failure returns the same error and, for tokens that fail before
//     signature verification, performs a dummy verification so timing does not
//     reveal how far a token got.

// ErrJWT is the only error callers see.
var ErrJWT = errors.New("auth: invalid token")

type jwtKey struct {
	kid string
	alg string // the only algorithm this key may be used with
	pub crypto.PublicKey
}

// JWKS is a cached key set with stale-if-error semantics.
type JWKS struct {
	fetch      func(ctx context.Context) ([]byte, error)
	refresh    time.Duration
	staleMax   time.Duration
	minRefresh time.Duration

	mu       sync.Mutex
	keys     map[string]jwtKey
	fetched  time.Time // last successful fetch
	attempt  time.Time // last attempt (success or not)
	fetching bool
	now      func() time.Time
}

func newJWKS(c config.JWT, version string) *JWKS {
	j := &JWKS{refresh: c.Refresh, staleMax: c.StaleMax, minRefresh: c.MinRefresh, now: time.Now}
	if j.refresh == 0 {
		j.refresh = 5 * time.Minute
	}
	if j.staleMax == 0 {
		j.staleMax = time.Hour
	}
	if j.minRefresh == 0 {
		j.minRefresh = 10 * time.Second
	}
	switch {
	case c.JWKSFile != "":
		path := c.JWKSFile
		j.fetch = func(context.Context) ([]byte, error) { return os.ReadFile(path) } //nolint:gosec // operator-supplied path
	default:
		url := c.JWKSURL
		cl := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil, MaxIdleConns: 2}}
		j.fetch = func(ctx context.Context) ([]byte, error) {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				return nil, err
			}
			req.Header.Set("User-Agent", "tripwire-gateway/"+version)
			resp, err := cl.Do(req)
			if err != nil {
				return nil, err
			}
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				return nil, fmt.Errorf("jwks: status %d", resp.StatusCode)
			}
			return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		}
	}
	return j
}

// lookup returns the key for kid. It refreshes when the cache is older than
// `refresh`, or (rate-limited by minRefresh) when kid is unknown, which is how a
// key rotation is picked up. A failed refresh keeps serving the previous keys
// until they are staleMax old (stale-if-error); after that nothing verifies.
func (j *JWKS) lookup(ctx context.Context, kid string) (jwtKey, bool) {
	j.mu.Lock()
	now := j.now()
	k, ok := j.keys[kid]
	due := j.keys == nil || now.Sub(j.fetched) >= j.refresh || (!ok && now.Sub(j.attempt) >= j.minRefresh)
	if due && now.Sub(j.attempt) < time.Second && j.keys != nil { // never hammer the endpoint
		due = false
	}
	if !due || j.fetching {
		stale := j.keys != nil && now.Sub(j.fetched) > j.staleMax
		j.mu.Unlock()
		return k, ok && !stale
	}
	j.fetching, j.attempt = true, now
	j.mu.Unlock()

	b, err := j.fetch(ctx)
	var keys map[string]jwtKey
	if err == nil {
		keys, err = parseJWKS(b)
	}

	j.mu.Lock()
	defer j.mu.Unlock()
	j.fetching = false
	if err == nil {
		j.keys, j.fetched = keys, j.now()
	}
	stale := j.keys == nil || j.now().Sub(j.fetched) > j.staleMax
	k, ok = j.keys[kid]
	return k, ok && !stale
}

type jwkDoc struct {
	Keys []struct {
		Kty string `json:"kty"`
		Kid string `json:"kid"`
		Use string `json:"use"`
		Alg string `json:"alg"`
		Crv string `json:"crv"`
		N   string `json:"n"`
		E   string `json:"e"`
		X   string `json:"x"`
		Y   string `json:"y"`
	} `json:"keys"`
}

func b64(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

func parseJWKS(b []byte) (map[string]jwtKey, error) {
	if _, err := jsonscan.Validate(b, jsonscan.DefaultLimits()); err != nil {
		return nil, err
	}
	var d jwkDoc
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, err
	}
	out := map[string]jwtKey{}
	for _, k := range d.Keys {
		if k.Kid == "" || k.Use == "enc" {
			continue
		}
		switch k.Kty {
		case "OKP":
			x, err := b64(k.X)
			if k.Crv != "Ed25519" || err != nil || len(x) != ed25519.PublicKeySize {
				continue
			}
			out[k.Kid] = jwtKey{k.Kid, "EdDSA", ed25519.PublicKey(x)}
		case "EC":
			x, e1 := b64(k.X)
			y, e2 := b64(k.Y)
			if k.Crv != "P-256" || e1 != nil || e2 != nil {
				continue
			}
			if len(x) > 32 || len(y) > 32 {
				continue
			}
			pt := make([]byte, 65) // 0x04 || X || Y, left-padded to 32 bytes each
			pt[0] = 4
			copy(pt[1+32-len(x):33], x)
			copy(pt[33+32-len(y):], y)
			pub, perr := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), pt) // validates the point is on the curve
			if perr != nil {
				continue
			}
			out[k.Kid] = jwtKey{k.Kid, "ES256", pub}
		case "RSA":
			n, e1 := b64(k.N)
			e, e2 := b64(k.E)
			if e1 != nil || e2 != nil || len(n)*8 < 2048 || len(e) > 4 {
				continue // RSA keys below 2048 bits are never used
			}
			out[k.Kid] = jwtKey{k.Kid, "RS256", &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}}
		}
	}
	if len(out) == 0 {
		return nil, errors.New("jwks: no usable keys")
	}
	return out, nil
}

// JWTVerifier verifies bearer tokens.
type JWTVerifier struct {
	cfg    config.JWT
	allow  map[string]bool
	jwks   *JWKS
	now    func() time.Time
	cache  *tokenCache
	dummyK ed25519.PublicKey
	dummyS []byte
}

// NewJWTVerifier builds a verifier from config.
func NewJWTVerifier(c config.JWT, version string) *JWTVerifier {
	v := &JWTVerifier{cfg: c, allow: map[string]bool{}, jwks: newJWKS(c, version), now: time.Now, cache: newTokenCache(1 << 16)}
	for _, a := range c.Algorithms {
		v.allow[a] = true
	}
	if v.cfg.AgentClaim == "" {
		v.cfg.AgentClaim = "sub"
	}
	if v.cfg.Leeway == 0 {
		v.cfg.Leeway = 30 * time.Second
	}
	pub, priv, _ := ed25519.GenerateKey(nil)
	v.dummyK, v.dummyS = pub, ed25519.Sign(priv, []byte("tripwire-dummy"))
	return v
}

type jwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	var one string
	if json.Unmarshal(b, &one) == nil {
		*a = audience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*a = many
	return nil
}

// Verify returns the agent id named by a valid token.
func (v *JWTVerifier) Verify(ctx context.Context, token string) (string, error) {
	now := v.now()
	h := sha256.Sum256([]byte(token))
	if agent, ok := v.cache.get(h, now); ok {
		return agent, nil
	}
	agent, exp, err := v.verify(ctx, token, now)
	if err != nil {
		return "", ErrJWT
	}
	ttl := exp
	if max := now.Add(5 * time.Minute); ttl.After(max) {
		ttl = max // a revoked key is honoured within five minutes, not at token exp
	}
	v.cache.put(h, agent, ttl)
	return agent, nil
}

func (v *JWTVerifier) dummy() { _ = ed25519.Verify(v.dummyK, []byte("tripwire-dummy"), v.dummyS) }

func (v *JWTVerifier) verify(ctx context.Context, token string, now time.Time) (agent string, exp time.Time, err error) {
	if len(token) > 8192 {
		v.dummy()
		return "", exp, ErrJWT
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		v.dummy()
		return "", exp, ErrJWT
	}
	hb, e1 := b64(parts[0])
	pb, e2 := b64(parts[1])
	sig, e3 := b64(parts[2])
	if e1 != nil || e2 != nil || e3 != nil {
		v.dummy()
		return "", exp, ErrJWT
	}
	lim := jsonscan.DefaultLimits()
	lim.MaxBytes = 4096
	if _, err := jsonscan.Validate(hb, lim); err != nil {
		v.dummy()
		return "", exp, ErrJWT
	}
	var hdr jwtHeader
	if err := json.Unmarshal(hb, &hdr); err != nil || !v.allow[hdr.Alg] {
		v.dummy() // includes alg "none", HS256 and anything not on the allow-list
		return "", exp, ErrJWT
	}
	key, ok := v.jwks.lookup(ctx, hdr.Kid)
	if !ok || key.alg != hdr.Alg { // the key's type decides the algorithm, not the header
		v.dummy()
		return "", exp, ErrJWT
	}
	signed := []byte(parts[0] + "." + parts[1])
	var sigOK bool
	switch hdr.Alg {
	case "EdDSA":
		sigOK = ed25519.Verify(key.pub.(ed25519.PublicKey), signed, sig)
	case "ES256":
		if len(sig) == 64 {
			d := sha256.Sum256(signed)
			sigOK = ecdsa.Verify(key.pub.(*ecdsa.PublicKey), d[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
		} else {
			v.dummy()
		}
	case "RS256":
		d := sha256.Sum256(signed)
		sigOK = rsa.VerifyPKCS1v15(key.pub.(*rsa.PublicKey), crypto.SHA256, d[:], sig) == nil
	}
	if !sigOK {
		return "", exp, ErrJWT
	}
	// claims, only after the signature is good
	if _, err := jsonscan.Validate(pb, lim); err != nil {
		return "", exp, ErrJWT
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(pb, &raw); err != nil {
		return "", exp, ErrJWT
	}
	var iss string
	var aud audience
	var expN, nbfN float64
	if json.Unmarshal(raw["iss"], &iss) != nil || iss != v.cfg.Issuer {
		return "", exp, ErrJWT
	}
	if json.Unmarshal(raw["aud"], &aud) != nil || !contains(aud, v.cfg.Audience) {
		return "", exp, ErrJWT
	}
	if json.Unmarshal(raw["exp"], &expN) != nil || expN <= 0 { // exp is required
		return "", exp, ErrJWT
	}
	exp = time.Unix(int64(expN), 0)
	if !now.Before(exp.Add(v.cfg.Leeway)) {
		return "", exp, ErrJWT
	}
	if v.cfg.MaxLifetime > 0 && exp.Sub(now) > v.cfg.MaxLifetime+v.cfg.Leeway {
		return "", exp, ErrJWT
	}
	if m, has := raw["nbf"]; has {
		if json.Unmarshal(m, &nbfN) != nil || now.Add(v.cfg.Leeway).Before(time.Unix(int64(nbfN), 0)) {
			return "", exp, ErrJWT
		}
	}
	if json.Unmarshal(raw[v.cfg.AgentClaim], &agent) != nil || agent == "" {
		return "", exp, ErrJWT
	}
	return agent, exp, nil
}

func contains(a audience, s string) bool {
	for _, v := range a {
		if v == s {
			return true
		}
	}
	return false
}

// tokenCache remembers verified tokens by hash until their expiry.
type tokenCache struct {
	max    int
	mu     sync.Mutex
	m      map[[32]byte]cacheEntry
	hits   atomic.Int64
	misses atomic.Int64
}

type cacheEntry struct {
	agent string
	until time.Time
}

func newTokenCache(max int) *tokenCache {
	return &tokenCache{max: max, m: make(map[[32]byte]cacheEntry)}
}

func (c *tokenCache) get(h [32]byte, now time.Time) (string, bool) {
	c.mu.Lock()
	e, ok := c.m[h]
	if ok && !now.Before(e.until) {
		delete(c.m, h)
		ok = false
	}
	c.mu.Unlock()
	if ok {
		c.hits.Add(1)
		return e.agent, true
	}
	c.misses.Add(1)
	return "", false
}

func (c *tokenCache) put(h [32]byte, agent string, until time.Time) {
	c.mu.Lock()
	if len(c.m) >= c.max { // bounded: drop an arbitrary tenth (map iteration order is random)
		n := 0
		for k := range c.m {
			delete(c.m, k)
			if n++; n > c.max/10 {
				break
			}
		}
	}
	c.m[h] = cacheEntry{agent, until}
	c.mu.Unlock()
}

// Stats reports cache hits and misses.
func (v *JWTVerifier) Stats() (hits, misses int64) { return v.cache.hits.Load(), v.cache.misses.Load() }
