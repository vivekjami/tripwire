SHELL := /bin/bash
.DEFAULT_GOAL := help
GO ?= go
FUZZTIME ?= 10s
BIN := .bin

export CGO_ENABLED ?= 0

.PHONY: help
help: ## list targets
	@grep -E '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-16s %s\n", $$1, $$2}'

# ---- toolchain & static checks ------------------------------------------------
.PHONY: tools
tools: ## install pinned analysis tools (staticcheck, govulncheck)
	$(GO) install honnef.co/go/tools/cmd/staticcheck@v0.8.2
	$(GO) install golang.org/x/vuln/cmd/govulncheck@latest

.PHONY: build
build: ## build every command into .bin/ (static, CGO off)
	$(GO) build -trimpath -o $(BIN)/ ./cmd/...

.PHONY: fmt
fmt: ## gofmt -w
	gofmt -w cmd internal

.PHONY: lint
lint: ## gofmt check, vet, staticcheck
	@test -z "$$(gofmt -l cmd internal)" || { echo "gofmt needed:"; gofmt -l cmd internal; exit 1; }
	$(GO) vet ./...
	@command -v staticcheck >/dev/null && staticcheck ./... || echo "staticcheck not installed (make tools); skipping"

.PHONY: vuln
vuln: ## govulncheck
	@command -v govulncheck >/dev/null && govulncheck ./... || echo "govulncheck not installed (make tools); skipping"

# ---- tests -------------------------------------------------------------------
.PHONY: test
test: ## unit + integration tests with the race detector (short: skips ~40 s of self-validation)
	$(GO) test -race -short ./...

.PHONY: test-all
test-all: ## everything, strict, incl. harness self-validation (use on the rig)
	$(GO) test -race -count=1 ./...

.PHONY: selfcheck
selfcheck: ## harness self-validation, STRICT thresholds (rig); TW_HEADROOM_RATE=30000 there
	$(GO) test ./internal/load -run SelfCheck -count=1 -v

.PHONY: selfcheck-laptop
selfcheck-laptop: ## same, timer-bound thresholds logged instead of failed (WSL2/laptops)
	TW_SELFCHECK_RELAXED=1 $(GO) test ./internal/load -run SelfCheck -count=1 -v

.PHONY: fuzz-smoke
fuzz-smoke: ## every Fuzz* target for FUZZTIME (default 10s)
	FUZZTIME=$(FUZZTIME) scripts/fuzz-smoke.sh

.PHONY: fuzz
fuzz: ## alias: make fuzz FUZZTIME=10m
	FUZZTIME=$(FUZZTIME) scripts/fuzz-smoke.sh

.PHONY: escape-check
escape-check: ## heap-escape regression gate for hot packages
	scripts/escape-check.sh

# ---- benchmarks --------------------------------------------------------------
.PHONY: bench-micro
bench-micro: ## Go microbenchmarks (compare with benchstat)
	$(GO) test -run '^$$' -bench . -benchmem -count=5 ./internal/... | tee .bench-micro.txt

.PHONY: bench-quick
bench-quick: ## ~60 s single-box harness sanity run (SHAPE ONLY)
	scripts/bench-quick.sh

.PHONY: bench
bench:
	@echo "make bench is the full 3-VM rig campaign (Phase 5). Phase 0 provides: make bench-quick, make rig-up, make selfcheck."; exit 1

.PHONY: eval repro failures
eval repro failures:
	@echo "target '$@' arrives in a later phase (see docs/IMPLEMENTATION_PLAN.md); not implemented in Phase 0"; exit 1

# ---- local dev stack ---------------------------------------------------------
.PHONY: dev-up dev-down
dev-up: ## mock + null proxy + Prometheus + Grafana (needs docker compose)
	docker compose -f deploy/compose/docker-compose.yml up --build -d
dev-down:
	docker compose -f deploy/compose/docker-compose.yml down

# ---- rig ---------------------------------------------------------------------
.PHONY: rig-up rig-down rig-status
rig-up: ## provision/prepare the 3-VM rig (see deploy/rig/README.md)
	deploy/rig/rig.sh up
rig-down: ## tear the rig down; ALWAYS run after a bench session
	deploy/rig/rig.sh down
rig-status:
	deploy/rig/rig.sh status

.PHONY: clean
clean:
	rm -rf $(BIN) .bench-quick .bench-micro.txt
