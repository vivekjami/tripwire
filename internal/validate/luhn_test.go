package validate

import (
	"math/rand/v2"
	"strings"
	"testing"
)

// Published, well-known test numbers (documented by the card networks and
// payment processors for testing; none is a real account).
var valid = []string{
	"4111111111111111", // Visa test
	"4012888888881881", // Visa test
	"5555555555554444", // Mastercard test
	"5105105105105100", // Mastercard test
	"378282246310005",  // Amex test
	"371449635398431",  // Amex test
	"6011111111111117", // Discover test
	"30569309025904",   // Diners test
	"79927398713",      // Wikipedia Luhn example
}

func TestLuhnValid(t *testing.T) {
	for _, s := range valid {
		if !Luhn(s) {
			t.Errorf("Luhn(%q) = false, want true", s)
		}
	}
}

func TestLuhnInvalid(t *testing.T) {
	for _, s := range []string{"", "1", "4111111111111112", "79927398710", "4111 1111 1111 1111", "abcd", "41111111111111x1"} {
		if Luhn(s) {
			t.Errorf("Luhn(%q) = true, want false", s)
		}
	}
}

func TestCheckDigitRoundTrip(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for i := 0; i < 20000; i++ {
		n := 12 + r.IntN(8)
		var b strings.Builder
		for j := 0; j < n; j++ {
			b.WriteByte(byte('0' + r.IntN(10)))
		}
		p := b.String()
		full := p + string(LuhnCheckDigit(p))
		if !Luhn(full) {
			t.Fatalf("prefix %q + check digit is not Luhn-valid: %q", p, full)
		}
	}
}

// Roughly 10% of random digit strings pass Luhn; the hard-negative corpus
// relies on this (ARCHITECTURE §6.9). Guard the property so a broken
// validator can't silently make that corpus meaningless.
func TestRandomPassRate(t *testing.T) {
	r := rand.New(rand.NewPCG(3, 4))
	pass := 0
	const n = 50000
	for i := 0; i < n; i++ {
		var b [16]byte
		for j := range b {
			b[j] = byte('0' + r.IntN(10))
		}
		if Luhn(string(b[:])) {
			pass++
		}
	}
	rate := float64(pass) / n
	if rate < 0.09 || rate > 0.11 {
		t.Fatalf("random 16-digit pass rate = %.4f, want ~0.10", rate)
	}
}

func FuzzLuhnCheckDigit(f *testing.F) {
	f.Add("411111111111111")
	f.Fuzz(func(t *testing.T, s string) {
		for i := 0; i < len(s); i++ {
			if s[i] < '0' || s[i] > '9' {
				return
			}
		}
		if len(s) == 0 {
			return
		}
		if !Luhn(s + string(LuhnCheckDigit(s))) {
			t.Fatalf("check digit for %q does not validate", s)
		}
	})
}
