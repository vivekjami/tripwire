package auth

import "strings"

// Glob is a compiled pattern where '*' matches any (possibly empty) run of
// bytes and everything else is literal. No normalization is applied to the
// subject: a name that does not match exactly is simply not in scope
// (ARCHITECTURE §8.2, T9: no lookalike or trailing-space fix-ups).
type Glob struct {
	exact string   // when no '*'
	parts []string // literal segments split on '*'
	wild  bool
}

// CompileGlob compiles a pattern.
func CompileGlob(p string) Glob {
	if !strings.Contains(p, "*") {
		return Glob{exact: p}
	}
	return Glob{parts: strings.Split(p, "*"), wild: true}
}

// Match reports whether s matches the pattern.
func (g Glob) Match(s string) bool {
	if !g.wild {
		return s == g.exact
	}
	first, last := g.parts[0], g.parts[len(g.parts)-1]
	if len(s) < len(first)+len(last) || !strings.HasPrefix(s, first) || !strings.HasSuffix(s, last) {
		return false
	}
	s = s[len(first) : len(s)-len(last)]
	for _, mid := range g.parts[1 : len(g.parts)-1] {
		i := strings.Index(s, mid)
		if i < 0 {
			return false
		}
		s = s[i+len(mid):]
	}
	return true
}
