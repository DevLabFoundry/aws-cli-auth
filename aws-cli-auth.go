package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/DevLabFoundry/aws-cli-auth/cmd"
	"github.com/rs/zerolog"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), []os.Signal{os.Interrupt, syscall.SIGTERM, os.Kill}...)
	defer stop()
	logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}).
		Level(zerolog.ErrorLevel).
		With().Timestamp().
		Logger()

	go func() {
		<-ctx.Done()
		stop()
		logger.Fatal().Msgf("\x1b[31minterrupted: %s\x1b[0m", ctx.Err())
	}()

	c := cmd.New(logger)
	c.WithSubCommands(cmd.SubCommands()...)

	if err := c.Execute(ctx); err != nil {
		logger.Fatal().Msgf("\x1b[31m%s\x1b[0m", err)
	}
}
