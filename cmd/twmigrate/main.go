// Command twmigrate applies the embedded ClickHouse migrations (deploy/ch).
//
//	twmigrate -addr 127.0.0.1:9000
//
// STATUS: compile-checked; not yet run against a ClickHouse server in this
// repository's environment.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/ClickHouse/ch-go"

	chmig "github.com/vivekjami/tripwire/deploy/ch"
	"github.com/vivekjami/tripwire/internal/lineage"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:9000", "ClickHouse native address")
	user := flag.String("user", "default", "user")
	pass := flag.String("password", "", "password (prefer the CH_PASSWORD env var)")
	flag.Parse()
	if *pass == "" {
		*pass = os.Getenv("CH_PASSWORD")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	c, err := ch.Dial(ctx, ch.Options{Address: *addr, User: *user, Password: *pass})
	if err != nil {
		fmt.Fprintln(os.Stderr, "twmigrate:", err)
		os.Exit(1)
	}
	defer c.Close()
	done, err := lineage.Migrate(ctx, c, chmig.FS, "migrations")
	for _, m := range done {
		fmt.Println("applied", m)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "twmigrate:", err)
		os.Exit(1)
	}
	if len(done) == 0 {
		fmt.Println("up to date")
	}
}
