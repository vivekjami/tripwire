package mock

import (
	"bufio"
	"fmt"
	"math"
	"math/rand/v2"
	"os"
	"strconv"
	"strings"
	"time"
)

// GapDist samples inter-event gaps.
type GapDist interface {
	Next(r *rand.Rand) time.Duration
}

type constGap time.Duration

func (g constGap) Next(*rand.Rand) time.Duration { return time.Duration(g) }

// lognormalGap has the given MEAN and shape sigma. mu = ln(mean) - sigma²/2 so
// that E[X] = mean regardless of sigma.
type lognormalGap struct{ mu, sigma float64 }

func (g lognormalGap) Next(r *rand.Rand) time.Duration {
	return time.Duration(math.Exp(g.mu + g.sigma*r.NormFloat64()))
}

type empiricalGap []time.Duration

func (g empiricalGap) Next(r *rand.Rand) time.Duration { return g[r.IntN(len(g))] }

// ParseGap parses a gap specification:
//
//	none | const:20ms | lognormal:20ms,0.4 | file:/path (one millisecond value per line)
func ParseGap(s string) (GapDist, error) {
	s = strings.TrimSpace(s)
	switch {
	case s == "" || s == "none":
		return constGap(0), nil
	case strings.HasPrefix(s, "const:"):
		d, err := time.ParseDuration(s[len("const:"):])
		if err != nil || d < 0 {
			return nil, fmt.Errorf("gap %q: bad duration", s)
		}
		return constGap(d), nil
	case strings.HasPrefix(s, "lognormal:"):
		parts := strings.Split(s[len("lognormal:"):], ",")
		if len(parts) != 2 {
			return nil, fmt.Errorf("gap %q: want lognormal:<mean>,<sigma>", s)
		}
		mean, err := time.ParseDuration(parts[0])
		if err != nil || mean <= 0 {
			return nil, fmt.Errorf("gap %q: bad mean", s)
		}
		sigma, err := strconv.ParseFloat(parts[1], 64)
		if err != nil || sigma < 0 {
			return nil, fmt.Errorf("gap %q: bad sigma", s)
		}
		return lognormalGap{mu: math.Log(float64(mean)) - sigma*sigma/2, sigma: sigma}, nil
	case strings.HasPrefix(s, "file:"):
		f, err := os.Open(s[len("file:"):])
		if err != nil {
			return nil, err
		}
		defer f.Close()
		var out empiricalGap
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			ms, err := strconv.ParseFloat(line, 64)
			if err != nil || ms < 0 {
				return nil, fmt.Errorf("gap file: bad value %q", line)
			}
			out = append(out, time.Duration(ms*float64(time.Millisecond)))
		}
		if err := sc.Err(); err != nil {
			return nil, err
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("gap file %q is empty", s)
		}
		return out, nil
	}
	return nil, fmt.Errorf("gap %q: unknown form", s)
}
