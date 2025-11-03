package main

import (
	"errors"
	"fmt"
	"os"

	"pistonmaster.net/pistonscan/internal/gui"
)

const usage = `PistonScan - IP scanning toolkit

Usage:
  pistonscan open   Launch the PistonScan interface.
  pistonscan help   Show this help message.
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
		if os.Getenv("PISTONSCAN_HEADLESS") == "1" {
			return nil
		}
		application := gui.New()
		return application.Run()
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
