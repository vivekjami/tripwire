// Package chmig embeds the ClickHouse migrations so the binary and the
// migration runner always agree on the schema.
package chmig

import "embed"

// FS holds the ordered *.sql migrations (NNNN_name.sql).
//
//go:embed migrations/*.sql
var FS embed.FS
