# Evaluation data: licences and provenance

Rule (IMPLEMENTATION_PLAN WP3.5): every text, list or model that enters the eval set or a detector is recorded here with source and licence **before** it is used. **No real credentials and no real personal data, ever.**

| Asset | Source | Licence | Used for | Status |
|---|---|---|---|---|
| Mock benign word list (`internal/mock/text.go`) | authored for this project | MIT (repo) | benign background in twmock streams | in use (Phase 0) |
| Generated PAN / AWS key / GitHub token / email values (`internal/gen`) | generated from a seeded PRNG; PANs Luhn-valid on documented issuer prefixes; emails only on RFC 2606 reserved domains; AWS/GitHub bodies random | n/a (synthetic) | ground-truth injection | in use (Phase 0) |
| Public-domain prose background | TBD (e.g. Project Gutenberg) | TBD, record per work | realistic FP measurement | **Phase 3** |
| First-name / surname / street gazetteers | TBD | TBD | PII.NAME/ADDRESS stage 2 | **Phase 3** |
| BurstGPT arrival trace | public trace referenced in README §6.3 | **verify at import** | W1 arrival process | **not yet imported; importer untested on the real file** (`internal/trace`) |
