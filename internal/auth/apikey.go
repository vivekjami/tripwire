package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

// API key format (ARCHITECTURE §8.1): tw_<agent_id>_<43 chars base64url of 32 random bytes>.
// Only SHA-256(pepper || key) is stored. The key is high-entropy, so a fast hash
// is appropriate (no password KDF), and comparison is constant-time.
const (
	keyPrefix = "tw_"
	secretLen = 43
	minPepper = 16
)

// GenerateKey creates a new key for agent and returns it with its stored hash.
func GenerateKey(agent string, pepper []byte) (key, hashHex string, err error) {
	if len(pepper) < minPepper {
		return "", "", errors.New("auth: pepper must be at least 16 bytes")
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", "", err
	}
	key = keyPrefix + agent + "_" + base64.RawURLEncoding.EncodeToString(raw[:])
	return key, HashKey(pepper, key), nil
}

// HashKey returns the hex SHA-256(pepper || key).
func HashKey(pepper []byte, key string) string {
	h := sha256.New()
	h.Write(pepper)
	h.Write([]byte(key))
	return hex.EncodeToString(h.Sum(nil))
}

// agentOf extracts the agent id from a well-formed key ("" if malformed).
func agentOf(key string) string {
	rest, ok := strings.CutPrefix(key, keyPrefix)
	if !ok {
		return ""
	}
	agent, secret, ok := strings.Cut(rest, "_")
	if !ok || agent == "" || len(secret) != secretLen {
		return ""
	}
	return agent
}

type keyEntry struct {
	hash      [32]byte
	notBefore time.Time
	notAfter  time.Time
}

func (e *keyEntry) activeAt(t time.Time) bool {
	return (e.notBefore.IsZero() || !t.Before(e.notBefore)) && (e.notAfter.IsZero() || t.Before(e.notAfter))
}

// keyStore verifies API keys. Failure behaviour is uniform: every call does one
// SHA-256 and at least one constant-time comparison whether the key is
// malformed, for an unknown agent, expired, or simply wrong, so response and
// latency do not distinguish those cases (ARCHITECTURE §8.1).
type keyStore struct {
	pepper  []byte
	byAgent map[string][]keyEntry
}

var dummyEntries = []keyEntry{{}}

// verify returns the agent id for a valid, currently-active key.
func (s *keyStore) verify(key string, now time.Time) (string, bool) {
	h := sha256.New()
	h.Write(s.pepper)
	h.Write([]byte(key))
	var sum [32]byte
	h.Sum(sum[:0])

	agent := agentOf(key)
	entries, known := s.byAgent[agent]
	if !known {
		entries = dummyEntries
	}
	match := 0
	for i := range entries { // no early exit: every rotation entry is compared
		eq := subtle.ConstantTimeCompare(sum[:], entries[i].hash[:])
		if entries[i].activeAt(now) {
			match |= eq
		}
	}
	if match == 1 && known && agent != "" {
		return agent, true
	}
	return "", false
}
