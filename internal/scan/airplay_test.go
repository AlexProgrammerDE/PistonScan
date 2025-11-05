package scan

import "testing"

func TestParseAirPlayResponse(t *testing.T) {
	sample := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
    <key>deviceid</key>
    <string>AA:BB:CC:DD:EE:FF</string>
    <key>model</key>
    <string>AppleTV6,2</string>
    <key>features</key>
    <integer>123456</integer>
</dict>
</plist>`)

	fields := parseAirPlayResponse(sample)
	if len(fields) != 3 {
		t.Fatalf("expected 3 fields, got %d: %v", len(fields), fields)
	}

	if fields["deviceid"] != "AA:BB:CC:DD:EE:FF" {
		t.Fatalf("expected deviceid preserved, got %q", fields["deviceid"])
	}

	if fields["model"] != "AppleTV6,2" {
		t.Fatalf("expected model preserved, got %q", fields["model"])
	}

	if fields["features"] != "123456" {
		t.Fatalf("expected features rendered as string, got %q", fields["features"])
	}
}

func TestShouldQueryAirPlay(t *testing.T) {
	services := []ServiceInfo{{Port: 7000, Protocol: "tcp", Service: "AirPlay"}}
	if !shouldQueryAirPlay(services) {
		t.Fatalf("expected AirPlay detection to trigger for tcp/7000")
	}

	other := []ServiceInfo{{Port: 7000, Protocol: "udp", Service: "AirPlay"}}
	if shouldQueryAirPlay(other) {
		t.Fatalf("expected AirPlay detection to skip non-TCP services")
	}
}

func TestNormaliseAirPlayValue(t *testing.T) {
	ascii := []byte("Test String")
	if got := normaliseAirPlayValue(ascii); got != "Test String" {
		t.Fatalf("expected ASCII bytes to convert to string, got %q", got)
	}

	binary := []byte{0x00, 0x01, 0x02}
	if got := normaliseAirPlayValue(binary); got != "000102" {
		t.Fatalf("expected binary bytes to be hex encoded, got %q", got)
	}

	nested := map[string]any{"name": "AirPlay", "active": true}
	if got := normaliseAirPlayValue(nested); got != "active=true, name=AirPlay" {
		t.Fatalf("unexpected nested normalisation: %q", got)
	}
}
