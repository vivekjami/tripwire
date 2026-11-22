# syntax=docker/dockerfile:1
# Multi-stage, static, non-root, distroless. Build one command per image:
#   docker build --build-arg BIN=twnull -t tripwire/twnull .
# Phase 0 ships the harness binaries (twmock, twnull, twload); the gateway
# (cmd/tripwire) arrives in Phase 1 and becomes the default BIN then.
ARG GO_VERSION=1.26.0
FROM golang:${GO_VERSION} AS build
ARG BIN=twnull
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOFLAGS=-trimpath go build -ldflags="-s -w" -o /out/${BIN} ./cmd/${BIN}

FROM gcr.io/distroless/static-debian12:nonroot
ARG BIN=twnull
COPY --from=build /out/${BIN} /app
USER nonroot:nonroot
ENTRYPOINT ["/app"]
