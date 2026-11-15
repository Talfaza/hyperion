package main

import (
	"context"
	"os"

	"github.com/Talfaza/hyperion/internal/cli"
)

// version is set at build time with -ldflags "-X main.version=..."
var version = "dev"

func main() {
	os.Exit(cli.Execute(context.Background(), version))
}
