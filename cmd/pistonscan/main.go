package main

import (
	"errors"
	"fmt"
	"os"
)

const usage = `PistonScan - IP scanning toolkit (work in progress)

Usage:
  pistonscan open   Open the PistonScan interface.
`

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		fmt.Print(usage)
		return nil
	}

	switch args[0] {
	case "open":
		fmt.Println("Opening PistonScan... (functionality coming soon)")
		return nil
	case "help", "--help", "-h":
		fmt.Print(usage)
		return nil
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func init() {
	// Ensure usage text ends with a newline so we can safely print it without fmt.Println.
	if len(usage) == 0 || usage[len(usage)-1] != '\n' {
		panic(errors.New("usage string must end with a newline"))
	}
}
