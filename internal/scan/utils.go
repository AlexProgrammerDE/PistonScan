package scan

import (
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	macLinePattern    = regexp.MustCompile(`(?i)([0-9a-f]{2}[:-]){5}([0-9a-f]{2})`)
	whitespacePattern = regexp.MustCompile(`\s+`)
)

func durationsToMillis(values []time.Duration) []float64 {
	if len(values) == 0 {
		return nil
	}
	out := make([]float64, 0, len(values))
	for _, v := range values {
		out = append(out, v.Seconds()*1000)
	}
	return out
}

func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	var out []string
	for _, v := range values {
		normalized := strings.TrimSpace(v)
		normalized = strings.TrimSuffix(normalized, ".")
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	sort.Strings(out)
	return out
}

func normaliseMAC(raw string) string {
	if raw == "" {
		return ""
	}
	raw = strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(raw, "-", ":"), ".", ":"))
	match := macLinePattern.FindString(raw)
	if match == "" {
		return ""
	}
	parts := strings.Split(match, ":")
	if len(parts) != 6 {
		return ""
	}
	for i := range parts {
		if len(parts[i]) == 1 {
			parts[i] = "0" + parts[i]
		}
	}
	return strings.Join(parts, ":")
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
