package mock

import (
	"math/rand/v2"
	"strings"

	"github.com/vivekjami/tripwire/internal/gen"
	"github.com/vivekjami/tripwire/internal/groundtruth"
)

// Corpus provenance (IMPLEMENTATION_PLAN WP0.2 asks for public-domain prose
// with source and licence recorded). Phase 0 uses a SYNTHETIC corpus built
// from the word list below, authored for this project (MIT, same as the repo).
// It is deliberately benign: it contains no digit runs, no '@', and no
// credential-shaped tokens, so any detection on it is a false positive. A real
// public-domain corpus (e.g. Project Gutenberg texts) replaces it in Phase 3
// for realistic false-positive measurement; see docs/adr/AMENDMENTS.md.
var words = strings.Fields(`the of and to in is that for it as was with be by on not he this are or his from at which but have an had they you were their one all we can her has there been if more when will would who so no
agent model request response stream token value tool result prompt secret record customer order account report data system service message file query user policy gateway network latency budget window buffer cache queue
quickly carefully later today again always never often sometimes together without between because while after before during under over through across around inside outside
read write send receive open close check build deploy review update create remove merge split join start finish continue wait retry
green quiet small large early simple clear steady careful common recent final second third different several another every
café señor naïve résumé über 日本語 😀 🙂`)

// buildText assembles benign prose of roughly targetRunes runes and embeds the
// given values at distinct random word slots, returning the text and the
// exact byte spans of each embedded value.
func buildText(r *rand.Rand, targetRunes int, vals []gen.Value) (string, []groundtruth.Span) {
	if targetRunes < 16 {
		targetRunes = 16
	}
	// Choose how many words we need, then pick distinct slots for the values.
	est := targetRunes/5 + 1
	nSlots := est + len(vals)
	slotOf := make(map[int]gen.Value, len(vals))
	for _, v := range vals {
		for {
			s := r.IntN(nSlots)
			if _, taken := slotOf[s]; !taken {
				slotOf[s] = v
				break
			}
		}
	}

	var b strings.Builder
	var spans []groundtruth.Span
	sentenceLeft := 6 + r.IntN(10)
	capNext := true
	for i, runes := 0, 0; i < nSlots || runes < targetRunes; i++ {
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		if v, ok := slotOf[i]; ok {
			spans = append(spans, groundtruth.Span{
				Class: v.Class, Value: v.Text, Norm: v.Norm,
				Hash: groundtruth.HashValue(v.Text), Offset: b.Len(), Len: len(v.Text),
			})
			b.WriteString(v.Text)
			runes += len([]rune(v.Text))
			continue
		}
		w := words[r.IntN(len(words))]
		if capNext && w[0] >= 'a' && w[0] <= 'z' {
			w = strings.ToUpper(w[:1]) + w[1:]
		}
		capNext = false
		b.WriteString(w)
		runes += len([]rune(w)) + 1
		sentenceLeft--
		if sentenceLeft <= 0 {
			b.WriteByte('.')
			sentenceLeft = 6 + r.IntN(10)
			capNext = true
		}
		if i >= nSlots && runes >= targetRunes {
			break
		}
	}
	return b.String(), spans
}
