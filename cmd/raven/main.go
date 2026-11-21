package main

import (
	"fmt"
	"os"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		// The root command sets SilenceErrors so cobra does not print the
		// error itself, which left every failure exiting 1 with no output.
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
