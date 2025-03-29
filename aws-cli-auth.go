package main

import (
	"context"

	"github.com/DevLabFoundry/aws-cli-auth/cmd"
)

func main() {
	cmd.Execute(context.Background())
}
