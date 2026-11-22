// Command twtrace writes a SYNTHETIC BurstGPT-shaped arrival trace.
//
// It exists because the real BurstGPT dataset could not be fetched or its
// licence checked in the Phase 0 environment. The output has the header and
// the burst character the importer expects (heavy-tailed rate switching,
// integer-second timestamps, heavy-tailed token counts) so that trace replay,
// rescaling and burst handling are exercised end to end. It is NOT BurstGPT
// and no result from it may be described as a replay of real traffic.
//
//	twtrace -rows 30000 -seed 7 > bench/data/synthetic-burstgpt.csv
package main

import (
	"bufio"
	"flag"
	"fmt"
	"math"
	"math/rand/v2"
	"os"
)

func main() {
	rows := flag.Int("rows", 30000, "number of requests")
	seed := flag.Uint64("seed", 7, "PRNG seed")
	base := flag.Float64("base-rate", 2, "baseline mean rate (req/s) before burst multipliers")
	flag.Parse()
	r := rand.New(rand.NewPCG(*seed, 0xb0b5))
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	fmt.Fprintln(w, "Timestamp,Model,Request tokens,Response tokens,Total tokens,Log Type")

	// Markov-modulated Poisson process: rate multiplier states with
	// exponentially distributed dwell times (mean 15 s): calm, normal, busy,
	// burst. This yields the over-dispersed second-by-second counts that make
	// replay different from a homogeneous Poisson process.
	mult := []float64{0.2, 1, 3, 9}
	state, t, nextSwitch := 1, 0.0, 15*r.ExpFloat64()
	for i := 0; i < *rows; {
		rate := *base * mult[state]
		t += r.ExpFloat64() / rate
		for t >= nextSwitch {
			state = r.IntN(len(mult))
			nextSwitch += 15 * r.ExpFloat64()
		}
		req := lognormal(r, 5.5, 1.0) // median ~245 tokens
		resp := lognormal(r, 5.0, 1.1)
		model, log := "ChatGPT", "Conversation log"
		if r.Float64() < 0.3 {
			model = "GPT-4"
		}
		if r.Float64() < 0.2 {
			log = "API log"
		}
		fmt.Fprintf(w, "%d,%s,%d,%d,%d,%s\n", int64(t), model, req, resp, req+resp, log)
		i++
	}
}

func lognormal(r *rand.Rand, mu, sigma float64) int {
	v := int(math.Exp(mu + sigma*r.NormFloat64()))
	return min(max(v, 1), 32000)
}
