package main

import "testing"

func TestRunWithoutArgsShowsUsage(t *testing.T) {
	if err := run(nil); err != nil {
		t.Fatalf("run returned error without args: %v", err)
	}
}

func TestRunOpenCommand(t *testing.T) {
	t.Setenv("PISTONSCAN_HEADLESS", "1")
	if err := run([]string{"open"}); err != nil {
		t.Fatalf("run returned error for open command: %v", err)
	}
}

func TestRunUnknownCommand(t *testing.T) {
	if err := run([]string{"unknown"}); err == nil {
		t.Fatal("expected error for unknown command")
	}
}
