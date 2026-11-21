// Command nulq is the NULQ Linux privilege-boundary assessment tool.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/dustin04x/nulq/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	os.Exit(cli.New().Run(ctx, os.Args[1:]))
}
