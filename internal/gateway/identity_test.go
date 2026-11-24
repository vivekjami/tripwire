package gateway

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vivekjami/tripwire/internal/config"
)

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func mintEd(t *testing.T, priv ed25519.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	h, _ := json.Marshal(map[string]any{"alg": "EdDSA", "kid": kid})
	p, _ := json.Marshal(claims)
	signing := b64(h) + "." + b64(p)
	return signing + "." + b64(ed25519.Sign(priv, []byte(signing)))
}

func TestJWTThroughTheDataPlane(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	jwks, _ := json.Marshal(map[string]any{"keys": []any{map[string]any{"kty": "OKP", "crv": "Ed25519", "kid": "k1", "x": b64(pub)}}})
	jf := filepath.Join(t.TempDir(), "jwks.json")
	if err := os.WriteFile(jf, jwks, 0o600); err != nil {
		t.Fatal(err)
	}
	var sawAuth string
	routes := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		io.WriteString(w, AgentFrom(r.Context()).ID)
	})
	r := start(t, func(c *config.Config) {
		c.Auth.JWT = config.JWT{Issuer: "https://idp.test", Audience: "tripwire", Algorithms: []string{"EdDSA"}, JWKSFile: jf}
	}, routes)
	claims := func(over map[string]any) map[string]any {
		c := map[string]any{"iss": "https://idp.test", "aud": "tripwire", "sub": "bot", "exp": time.Now().Add(time.Hour).Unix()}
		for k, v := range over {
			c[k] = v
		}
		return c
	}
	resp, body := do(t, http.DefaultClient, "GET", r.dataURL+"/x", mintEd(t, priv, "k1", claims(nil)), nil)
	if resp.StatusCode != 200 || body != "bot" || sawAuth != "" {
		t.Fatalf("valid JWT: %d %q authHeaderSeenByRoutes=%q", resp.StatusCode, body, sawAuth)
	}
	// API keys keep working alongside JWT
	if resp, _ := do(t, http.DefaultClient, "GET", r.dataURL+"/x", r.key, nil); resp.StatusCode != 200 {
		t.Fatalf("API key broken by enabling JWT: %d", resp.StatusCode)
	}
	// failures are uniform with API-key failures
	_, wantBody := do(t, http.DefaultClient, "GET", r.dataURL+"/x", "tw_bot_"+strings.Repeat("a", 43), nil)
	for name, tok := range map[string]string{
		"expired":   mintEd(t, priv, "k1", claims(map[string]any{"exp": time.Now().Add(-time.Hour).Unix()})),
		"wrong aud": mintEd(t, priv, "k1", claims(map[string]any{"aud": "x"})),
		"unknown":   mintEd(t, priv, "k1", claims(map[string]any{"sub": "ghost"})),
		"wrong key": mintEd(t, func() ed25519.PrivateKey { _, p, _ := ed25519.GenerateKey(rand.Reader); return p }(), "k1", claims(nil)),
	} {
		resp, body := do(t, http.DefaultClient, "GET", r.dataURL+"/x", tok, nil)
		if resp.StatusCode != 401 || body != wantBody {
			t.Errorf("%s: %d %q (must equal the API-key failure %q)", name, resp.StatusCode, body, wantBody)
		}
	}
}

// ---- mTLS --------------------------------------------------------------------------

type ca struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newCA(t *testing.T, cn string) *ca {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	c, _ := x509.ParseCertificate(der)
	return &ca{c, k, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func (c *ca) client(t *testing.T, uri string) tls.Certificate {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	u, _ := url.Parse(uri)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "client"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		URIs: []*url.URL{u}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, c.cert, &k.PublicKey, c.key)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

func TestMTLSIdentityMapping(t *testing.T) {
	good, other := newCA(t, "good"), newCA(t, "other")
	cdir := t.TempDir()
	writePair(t, cdir, "srv")
	caFile := filepath.Join(cdir, "ca.pem")
	if err := os.WriteFile(caFile, good.pem, 0o600); err != nil {
		t.Fatal(err)
	}
	routes := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, AgentFrom(r.Context()).ID) })
	rr := start(t, func(c *config.Config) {
		c.Listen.TLS = config.TLS{CertFile: filepath.Join(cdir, "c.pem"), KeyFile: filepath.Join(cdir, "k.pem"), ClientCAFile: caFile}
		c.Agents = append(c.Agents, config.Agent{ID: "svc", Tenant: "t", Models: []string{"*"}})
		c.Auth.MTLS = []config.MTLSMapping{{URISAN: "spiffe://prod/billing", Agent: "svc"}}
	}, routes)
	mk := func(cert *tls.Certificate) *http.Client {
		cfg := &tls.Config{InsecureSkipVerify: true} //nolint:gosec // test server uses a throwaway self-signed cert
		if cert != nil {
			cfg.Certificates = []tls.Certificate{*cert}
		}
		return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: 3 * time.Second}
	}
	known := good.client(t, "spiffe://prod/billing")
	unknown := good.client(t, "spiffe://prod/stranger")
	rogue := other.client(t, "spiffe://prod/billing") // right SAN, wrong CA

	if resp, body := do(t, mk(&known), "GET", rr.dataURL+"/x", "", nil); resp.StatusCode != 200 || body != "svc" {
		t.Fatalf("mTLS identity: %d %q", resp.StatusCode, body)
	}
	if resp, _ := do(t, mk(&unknown), "GET", rr.dataURL+"/x", "", nil); resp.StatusCode != 401 {
		t.Fatalf("unmapped SAN: %d", resp.StatusCode)
	}
	if resp, _ := do(t, mk(nil), "GET", rr.dataURL+"/x", "", nil); resp.StatusCode != 401 {
		t.Fatalf("no credentials at all: %d", resp.StatusCode)
	}
	// A certificate from an untrusted CA never authenticates: either the handshake fails, or
	// (Go clients only send certificates issued by a CA the server advertised) the request
	// arrives without a certificate and is rejected as unauthenticated.
	if resp, err := mk(&rogue).Get(rr.dataURL + "/x"); err == nil {
		resp.Body.Close()
		if resp.StatusCode != 401 {
			t.Fatalf("a certificate from an untrusted CA was not rejected: %d", resp.StatusCode)
		}
	}
	// bearer API key alone still works on the TLS listener
	if resp, body := do(t, mk(nil), "GET", rr.dataURL+"/x", rr.key, nil); resp.StatusCode != 200 || body != "bot" {
		t.Fatalf("API key over TLS: %d %q", resp.StatusCode, body)
	}
	// two identities that disagree are refused (certificate says svc, key says bot)
	if resp, _ := do(t, mk(&known), "GET", rr.dataURL+"/x", rr.key, nil); resp.StatusCode != 401 {
		t.Fatalf("conflicting identities accepted: %d", resp.StatusCode)
	}
}
