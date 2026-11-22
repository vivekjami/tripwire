package load

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// newClient builds the load client. HTTP/1.1 keep-alive with a very large idle
// pool by default; h2c (cleartext HTTP/2) when requested. Compression is off:
// the gateway negotiates identity upstream and the harness must not add its own
// CPU cost or change byte counts.
//
// For https targets, tlsCA names a PEM file of trusted roots (certificate
// verification is never disabled) and h2TLS enables HTTP/2 via ALPN.
func newClient(h2c bool, tlsCA string, h2TLS bool) (*http.Client, error) {
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	if tlsCA != "" {
		pem, err := os.ReadFile(tlsCA)
		if err != nil {
			return nil, fmt.Errorf("load: -tls-ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("load: -tls-ca %s: no certificates found", tlsCA)
		}
		protos := new(http.Protocols)
		protos.SetHTTP1(!h2TLS)
		protos.SetHTTP2(h2TLS)
		return &http.Client{Transport: &http.Transport{
			DialContext: d.DialContext, MaxIdleConnsPerHost: 1 << 20, IdleConnTimeout: 90 * time.Second,
			DisableCompression: true, Protocols: protos,
			TLSClientConfig:       &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
			HTTP2:                 &http.HTTP2Config{MaxConcurrentStreams: 1 << 16},
			ResponseHeaderTimeout: 60 * time.Second,
		}}, nil
	}
	if h2c {
		// Cleartext HTTP/2 with prior knowledge, via the standard library
		// (Go 1.24+); golang.org/x/net/http2 and h2c are deprecated for this.
		tr := &http.Transport{
			DialContext: d.DialContext, MaxIdleConnsPerHost: 1 << 20, IdleConnTimeout: 90 * time.Second,
			DisableCompression: true, Protocols: new(http.Protocols),
			HTTP2: &http.HTTP2Config{MaxConcurrentStreams: 1 << 16},
		}
		tr.Protocols.SetUnencryptedHTTP2(true)
		return &http.Client{Transport: tr}, nil
	}
	return &http.Client{Transport: &http.Transport{
		DialContext:           d.DialContext,
		MaxIdleConns:          0, // unlimited
		MaxIdleConnsPerHost:   1 << 20,
		IdleConnTimeout:       90 * time.Second,
		DisableCompression:    true,
		ForceAttemptHTTP2:     false,
		TLSNextProto:          map[string]func(string, *tls.Conn) http.RoundTripper{},
		ResponseHeaderTimeout: 60 * time.Second,
		ReadBufferSize:        16 << 10,
		WriteBufferSize:       4 << 10,
	}}, nil
}

// scrapeCPU reads process_cpu_seconds_total from a Prometheus text endpoint.
func scrapeCPU(url string) (float64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(io.LimitReader(resp.Body, 8<<20))
	sc.Buffer(make([]byte, 1<<20), 8<<20)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "process_cpu_seconds_total "); ok {
			return strconv.ParseFloat(strings.TrimSpace(v), 64)
		}
	}
	return 0, io.ErrUnexpectedEOF
}
