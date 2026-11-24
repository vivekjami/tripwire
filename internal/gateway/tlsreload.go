package gateway

import (
	"crypto/tls"
	"os"
	"sync"
	"time"
)

// certReloader serves a certificate that is re-read when either file changes
// (cert hot-reload, WP1.1). A bad new pair never replaces a good one: the old
// certificate keeps being served and the failure is counted.
type certReloader struct {
	certFile, keyFile string
	every             time.Duration // minimum time between stat() calls

	mu       sync.Mutex
	cert     *tls.Certificate
	certMod  time.Time
	keyMod   time.Time
	lastStat time.Time
	onResult func(ok bool)
}

func newCertReloader(certFile, keyFile string, onResult func(ok bool)) (*certReloader, error) {
	r := &certReloader{certFile: certFile, keyFile: keyFile, every: time.Second, onResult: onResult}
	if err := r.load(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *certReloader) load() error {
	c, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return err
	}
	cs, err1 := os.Stat(r.certFile)
	ks, err2 := os.Stat(r.keyFile)
	if err1 != nil || err2 != nil {
		return err1
	}
	r.cert, r.certMod, r.keyMod = &c, cs.ModTime(), ks.ModTime()
	return nil
}

// GetCertificate is tls.Config.GetCertificate.
func (r *certReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if now := time.Now(); now.Sub(r.lastStat) >= r.every {
		r.lastStat = now
		cs, err1 := os.Stat(r.certFile)
		ks, err2 := os.Stat(r.keyFile)
		if err1 == nil && err2 == nil && (!cs.ModTime().Equal(r.certMod) || !ks.ModTime().Equal(r.keyMod)) {
			oldCert := r.cert
			if err := r.load(); err != nil {
				r.cert, r.certMod, r.keyMod = oldCert, cs.ModTime(), ks.ModTime() // keep serving the old pair; do not retry until it changes again
				if r.onResult != nil {
					r.onResult(false)
				}
			} else if r.onResult != nil {
				r.onResult(true)
			}
		}
	}
	return r.cert, nil
}
