package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/DevLabFoundry/aws-cli-auth/cmd"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), []os.Signal{os.Interrupt, syscall.SIGTERM, os.Kill}...)
	defer stop()

	go func() {
		<-ctx.Done()
		stop()
		log.Printf("\x1b[31minterrupted: %s\x1b[0m", ctx.Err())
		os.Exit(0)
	}()

	c := cmd.New()
	c.WithSubCommands(cmd.SubCommands()...)

	if err := c.Execute(ctx); err != nil {
		log.Fatalf("\x1b[31m%s\x1b[0m", err)
	}
}
