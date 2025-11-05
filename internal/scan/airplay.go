package scan

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"howett.net/plist"
)

const (
	airPlayPort            = 7000
	maxAirPlayResponseSize = 1 << 20 // 1 MiB safety cap
	airPlayClientTimeout   = 1500 * time.Millisecond
)

// fetchAirPlayInfo retrieves metadata exposed by AirPlay endpoints on the host.
func fetchAirPlayInfo(ctx context.Context, host string) *AirPlayInfo {
	if host == "" {
		return nil
	}

	client := &http.Client{Timeout: airPlayClientTimeout}
	endpoints := []string{"info", "server-info"}

	for _, endpoint := range endpoints {
		url := fmt.Sprintf("http://%s/%s", net.JoinHostPort(host, strconv.Itoa(airPlayPort)), endpoint)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		data, err := io.ReadAll(io.LimitReader(resp.Body, maxAirPlayResponseSize))
		resp.Body.Close()
		if err != nil || resp.StatusCode != http.StatusOK {
			continue
		}

		fields := parseAirPlayResponse(data)
		if len(fields) == 0 {
			continue
		}

		return &AirPlayInfo{
			Endpoint: endpoint,
			Fields:   fields,
		}
	}

	return nil
}

func shouldQueryAirPlay(services []ServiceInfo) bool {
	for _, svc := range services {
		if svc.Port == airPlayPort && strings.EqualFold(svc.Protocol, "tcp") {
			return true
		}
	}
	return false
}

func parseAirPlayResponse(data []byte) map[string]string {
	if len(data) == 0 {
		return nil
	}

	var payload any
	if _, err := plist.Unmarshal(data, &payload); err != nil {
		return nil
	}

	rawMap, ok := payload.(map[string]any)
	if !ok || len(rawMap) == 0 {
		return nil
	}

	keys := make([]string, 0, len(rawMap))
	for key := range rawMap {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	fields := make(map[string]string, len(rawMap))
	for _, key := range keys {
		if value := normaliseAirPlayValue(rawMap[key]); value != "" {
			fields[key] = value
		}
	}

	if len(fields) == 0 {
		return nil
	}

	return fields
}

func normaliseAirPlayValue(value any) string {
	switch v := value.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(v)
	case fmt.Stringer:
		return strings.TrimSpace(v.String())
	case []byte:
		if len(v) == 0 {
			return ""
		}
		if utf8.Valid(v) && isPrintable(v) {
			return strings.TrimSpace(string(v))
		}
		return strings.ToUpper(hex.EncodeToString(v))
	case bool:
		if v {
			return "true"
		}
		return "false"
	case int, int32, int64, uint, uint32, uint64, float32, float64:
		return fmt.Sprintf("%v", v)
	case time.Time:
		return v.Format(time.RFC3339)
	case []any:
		var parts []string
		for _, item := range v {
			if part := normaliseAirPlayValue(item); part != "" {
				parts = append(parts, part)
			}
		}
		return strings.Join(parts, ", ")
	case map[string]any:
		if len(v) == 0 {
			return ""
		}
		nestedKeys := make([]string, 0, len(v))
		for key := range v {
			nestedKeys = append(nestedKeys, key)
		}
		sort.Strings(nestedKeys)
		var segments []string
		for _, key := range nestedKeys {
			if part := normaliseAirPlayValue(v[key]); part != "" {
				segments = append(segments, fmt.Sprintf("%s=%s", key, part))
			}
		}
		return strings.Join(segments, ", ")
	default:
		return fmt.Sprintf("%v", v)
	}
}

func isPrintable(data []byte) bool {
	for _, r := range string(data) {
		if r < 0x20 && r != '\n' && r != '\r' && r != '\t' {
			return false
		}
	}
	return true
}
