package scan

import "testing"

func TestResolveTargetsSingleIP(t *testing.T) {
	targets, err := resolveTargets("192.168.1.10")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(targets))
	}
	if targets[0] != "192.168.1.10" {
		t.Fatalf("expected target to equal input IP, got %s", targets[0])
	}
}

func TestResolveTargetsCIDR(t *testing.T) {
	targets, err := resolveTargets("10.0.0.0/30")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(targets) != 4 {
		t.Fatalf("expected 4 targets, got %d", len(targets))
	}
	expected := []string{"10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3"}
	for i, target := range targets {
		if target != expected[i] {
			t.Fatalf("target %d: expected %s, got %s", i, expected[i], target)
		}
	}
}

func TestConfigValidate(t *testing.T) {
	cfg := Config{Subnet: "192.168.1.0/30", ThreadLimit: 2, DelayMs: 0}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}

	bad := []Config{
		{Subnet: "", ThreadLimit: 1, DelayMs: 0},
		{Subnet: "192.168.1.0/30", ThreadLimit: 0, DelayMs: 0},
		{Subnet: "192.168.1.0/30", ThreadLimit: 1, DelayMs: -1},
	}
	for idx, c := range bad {
		if err := c.Validate(); err == nil {
			t.Fatalf("expected validation error for config %d", idx)
		}
	}
}
