# bench/data

`synthetic-burstgpt.csv` is **generated**, not committed: `.bin/twtrace -rows 30000` (deterministic, seed 7).
It is a **synthetic** arrival trace with BurstGPT's *assumed* header
(`Timestamp,Model,Request tokens,Response tokens,Total tokens,Log Type`) and a Markov-modulated Poisson
process (rate multipliers 0.2/1/3/9, mean dwell 15 s). It exists to exercise trace replay, rescaling and
burst handling. It is **not** BurstGPT; results from it must never be described as a real-traffic replay.
Fetching the real dataset and verifying its schema/licence remains an open item (docs/phases/P0.md).
