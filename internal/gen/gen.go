// Package gen produces synthetic, checksum-valid but FAKE sensitive values for
// the mock upstream's ground-truth injection and (from Phase 3) the evaluation
// set. Rule: never use real credentials or real personal data. Every value
// produced here is generated from a seeded PRNG.
package gen

import (
	"fmt"
	"math/rand/v2"
	"sort"
	"strings"

	"github.com/vivekjami/tripwire/internal/validate"
)

// Value is one generated sensitive value.
type Value struct {
	Class string // taxonomy class, e.g. PCI.PAN
	Text  string // exactly as it should appear in clear text (may include separators)
	Norm  string // normalized form (digits only for PAN); equals Text when no normalization applies
}

// Generator produces values of one class.
type Generator interface {
	Class() string
	Generate(r *rand.Rand) Value
}

var registry = map[string]Generator{}

func register(g Generator) { registry[g.Class()] = g }

func init() {
	register(PAN{})
	register(AWSAccessKey{})
	register(GitHubToken{})
	register(Email{})
}

// For returns the generator for a class.
func For(class string) (Generator, bool) { g, ok := registry[class]; return g, ok }

// Classes lists classes that have a generator, sorted.
func Classes() []string {
	out := make([]string, 0, len(registry))
	for c := range registry {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// NewRand returns a deterministic PRNG for a seed.
func NewRand(seed int64) *rand.Rand {
	return rand.New(rand.NewPCG(uint64(seed), uint64(seed)^0x9e3779b97f4a7c15))
}

// ---- PCI.PAN -------------------------------------------------------------

// PAN generates Luhn-valid card numbers across issuer ranges, rendered plain,
// space-grouped or hyphen-grouped.
type PAN struct{}

type issuer struct {
	prefix string
	length int
	groups []int
}

var issuers = []issuer{
	{"4", 16, []int{4, 4, 4, 4}},  // Visa
	{"51", 16, []int{4, 4, 4, 4}}, // Mastercard 51-55
	{"52", 16, []int{4, 4, 4, 4}},
	{"53", 16, []int{4, 4, 4, 4}},
	{"54", 16, []int{4, 4, 4, 4}},
	{"55", 16, []int{4, 4, 4, 4}},
	{"34", 15, []int{4, 6, 5}}, // Amex
	{"37", 15, []int{4, 6, 5}},
	{"6011", 16, []int{4, 4, 4, 4}}, // Discover
}

func (PAN) Class() string { return "PCI.PAN" }

func (PAN) Generate(r *rand.Rand) Value {
	is := issuers[r.IntN(len(issuers))]
	var b strings.Builder
	b.WriteString(is.prefix)
	for b.Len() < is.length-1 {
		b.WriteByte(byte('0' + r.IntN(10)))
	}
	body := b.String()
	digits := body + string(validate.LuhnCheckDigit(body))

	sep := ""
	switch r.IntN(3) {
	case 1:
		sep = " "
	case 2:
		sep = "-"
	}
	text := digits
	if sep != "" {
		parts := make([]string, 0, len(is.groups))
		pos := 0
		for _, g := range is.groups {
			parts = append(parts, digits[pos:pos+g])
			pos += g
		}
		text = strings.Join(parts, sep)
	}
	return Value{Class: "PCI.PAN", Text: text, Norm: digits}
}

// ---- SECRET.AWS_ACCESS_KEY ----------------------------------------------

// AWSAccessKey generates AKIA/ASIA + 16 chars of [A-Z2-7]. The body is random:
// the value is format-valid and fake.
type AWSAccessKey struct{}

func (AWSAccessKey) Class() string { return "SECRET.AWS_ACCESS_KEY" }

func (AWSAccessKey) Generate(r *rand.Rand) Value {
	const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	pfx := "AKIA"
	if r.IntN(4) == 0 {
		pfx = "ASIA"
	}
	b := make([]byte, 16)
	for i := range b {
		b[i] = alpha[r.IntN(len(alpha))]
	}
	t := pfx + string(b)
	return Value{Class: "SECRET.AWS_ACCESS_KEY", Text: t, Norm: t}
}

// ---- SECRET.GITHUB_TOKEN -------------------------------------------------

// GitHubToken generates ghp_ + 36 base62 chars. Real tokens embed a checksum;
// ARCHITECTURE §6.2 says to verify that format against current GitHub docs
// before relying on it, so these fakes do NOT claim checksum validity.
type GitHubToken struct{}

func (GitHubToken) Class() string { return "SECRET.GITHUB_TOKEN" }

func (GitHubToken) Generate(r *rand.Rand) Value {
	const alpha = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	b := make([]byte, 36)
	for i := range b {
		b[i] = alpha[r.IntN(len(alpha))]
	}
	t := "ghp_" + string(b)
	return Value{Class: "SECRET.GITHUB_TOKEN", Text: t, Norm: t}
}

// ---- PII.CONTACT.EMAIL ---------------------------------------------------

// Email generates addresses on reserved example domains (RFC 2606), so no
// generated address can belong to a real mailbox.
type Email struct{}

func (Email) Class() string { return "PII.CONTACT.EMAIL" }

var (
	firstNames = []string{"alex", "sam", "jordan", "taylor", "morgan", "casey", "riley", "jamie", "avery", "quinn", "devon", "robin"}
	lastNames  = []string{"smith", "chen", "garcia", "khan", "nowak", "silva", "ito", "okafor", "larsen", "rossi", "dubois", "patel"}
	domains    = []string{"example.com", "example.org", "example.net"}
)

func (Email) Generate(r *rand.Rand) Value {
	local := firstNames[r.IntN(len(firstNames))]
	switch r.IntN(3) {
	case 0:
		local += "." + lastNames[r.IntN(len(lastNames))]
	case 1:
		local += fmt.Sprintf("%d", r.IntN(100))
	default:
		local += "_" + lastNames[r.IntN(len(lastNames))]
	}
	t := local + "@" + domains[r.IntN(len(domains))]
	return Value{Class: "PII.CONTACT.EMAIL", Text: t, Norm: strings.ToLower(t)}
}
