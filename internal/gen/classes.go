package gen

import (
	"bytes"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Class is one entry of the data-class taxonomy (ARCHITECTURE §6.2).
type Class struct {
	Name         string   `yaml:"name"`
	Validators   []string `yaml:"validators"`
	Tier         string   `yaml:"tier"`        // T1..T4 streaming hold-back tier (§5.4)
	Linkability  string   `yaml:"linkability"` // tenant | session (§10.2)
	Severity     string   `yaml:"severity"`    // low | medium | high | critical
	Stage1       string   `yaml:"stage1"`
	ContextOnly  bool     `yaml:"context_only"`
	OnUncertain  string   `yaml:"on_uncertain"` // act | record | allow (§6.6)
	FPPer1K      float64  `yaml:"fp_per_1k"`    // target false positives per 1,000 benign requests
	HasGenerator bool     `yaml:"-"`
}

// Taxonomy is the parsed eval/classes.yaml.
type Taxonomy struct {
	Version int     `yaml:"version"`
	Classes []Class `yaml:"classes"`
}

var (
	validTiers   = map[string]bool{"T1": true, "T2": true, "T3": true, "T4": true, "n/a": true}
	validLink    = map[string]bool{"tenant": true, "session": true}
	validSev     = map[string]bool{"low": true, "medium": true, "high": true, "critical": true}
	validUncertn = map[string]bool{"act": true, "record": true, "allow": true}
)

// LoadTaxonomy strictly parses and validates the class registry. Unknown
// fields are rejected (config hygiene rule, IMPLEMENTATION_PLAN §2).
func LoadTaxonomy(path string) (*Taxonomy, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseTaxonomy(raw)
}

// ParseTaxonomy parses taxonomy YAML bytes.
func ParseTaxonomy(raw []byte) (*Taxonomy, error) {
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	var t Taxonomy
	if err := dec.Decode(&t); err != nil {
		return nil, fmt.Errorf("classes: %w", err)
	}
	seen := map[string]bool{}
	for i := range t.Classes {
		c := &t.Classes[i]
		if c.Name == "" {
			return nil, fmt.Errorf("classes[%d]: empty name", i)
		}
		if seen[c.Name] {
			return nil, fmt.Errorf("classes: duplicate class %q", c.Name)
		}
		seen[c.Name] = true
		if !validTiers[c.Tier] {
			return nil, fmt.Errorf("class %s: bad tier %q", c.Name, c.Tier)
		}
		if !validLink[c.Linkability] {
			return nil, fmt.Errorf("class %s: bad linkability %q", c.Name, c.Linkability)
		}
		if !validSev[c.Severity] {
			return nil, fmt.Errorf("class %s: bad severity %q", c.Name, c.Severity)
		}
		if c.OnUncertain != "" && !validUncertn[c.OnUncertain] {
			return nil, fmt.Errorf("class %s: bad on_uncertain %q", c.Name, c.OnUncertain)
		}
		_, c.HasGenerator = For(c.Name)
	}
	return &t, nil
}

// Find returns a class by name.
func (t *Taxonomy) Find(name string) (*Class, bool) {
	for i := range t.Classes {
		if t.Classes[i].Name == name {
			return &t.Classes[i], true
		}
	}
	return nil, false
}
