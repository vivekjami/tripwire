package gen

import (
	"strings"
	"testing"

	"github.com/vivekjami/tripwire/internal/validate"
)

func TestPANValidAndDeterministic(t *testing.T) {
	g := PAN{}
	r1, r2 := NewRand(7), NewRand(7)
	seenSep := map[bool]bool{}
	for i := 0; i < 5000; i++ {
		a, b := g.Generate(r1), g.Generate(r2)
		if a != b {
			t.Fatalf("not deterministic: %+v vs %+v", a, b)
		}
		if !validate.Luhn(a.Norm) {
			t.Fatalf("PAN %q not Luhn valid", a.Norm)
		}
		if n := len(a.Norm); n != 15 && n != 16 {
			t.Fatalf("PAN length %d", n)
		}
		stripped := strings.NewReplacer(" ", "", "-", "").Replace(a.Text)
		if stripped != a.Norm {
			t.Fatalf("text %q does not normalize to %q", a.Text, a.Norm)
		}
		seenSep[a.Text != a.Norm] = true
	}
	if !seenSep[true] || !seenSep[false] {
		t.Fatal("expected both plain and separated renderings")
	}
}

func TestAWSAndGitHubShapes(t *testing.T) {
	r := NewRand(1)
	for i := 0; i < 1000; i++ {
		a := AWSAccessKey{}.Generate(r).Text
		if len(a) != 20 || (!strings.HasPrefix(a, "AKIA") && !strings.HasPrefix(a, "ASIA")) {
			t.Fatalf("bad AWS key %q", a)
		}
		g := GitHubToken{}.Generate(r).Text
		if len(g) != 40 || !strings.HasPrefix(g, "ghp_") {
			t.Fatalf("bad GitHub token %q", g)
		}
		e := Email{}.Generate(r).Text
		if !strings.Contains(e, "@example.") {
			t.Fatalf("email %q not on a reserved domain", e)
		}
	}
}

func TestTaxonomyLoads(t *testing.T) {
	tx, err := LoadTaxonomy("../../eval/classes.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(tx.Classes) < 20 {
		t.Fatalf("only %d classes", len(tx.Classes))
	}
	// Every class that has a generator must be in the taxonomy.
	for _, c := range Classes() {
		if _, ok := tx.Find(c); !ok {
			t.Errorf("generator for %s has no taxonomy entry", c)
		}
	}
	if c, _ := tx.Find("PCI.PAN"); c == nil || !c.HasGenerator || c.Tier != "T1" {
		t.Errorf("PCI.PAN misconfigured: %+v", c)
	}
}

func TestTaxonomyRejectsUnknownField(t *testing.T) {
	_, err := ParseTaxonomy([]byte("version: 1\nclasses:\n  - {name: X, tier: T1, linkability: tenant, severity: low, bogus: 1}\n"))
	if err == nil {
		t.Fatal("expected unknown-field rejection")
	}
}

func TestTaxonomyRejectsDuplicates(t *testing.T) {
	_, err := ParseTaxonomy([]byte("version: 1\nclasses:\n  - {name: X, tier: T1, linkability: tenant, severity: low}\n  - {name: X, tier: T1, linkability: tenant, severity: low}\n"))
	if err == nil {
		t.Fatal("expected duplicate rejection")
	}
}
