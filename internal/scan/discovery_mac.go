package scan

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/endobit/oui"
)

func lookupMACAddress(ctx context.Context, host string) string {
	if mac := lookupMACFromProc(host); mac != "" {
		return mac
	}
	return lookupMACViaARPCommand(ctx, host)
}

func lookupMACFromProc(host string) string {
	data, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return ""
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines[1:] {
		fields := whitespacePattern.Split(strings.TrimSpace(line), -1)
		if len(fields) < 4 {
			continue
		}
		if fields[0] == host {
			if mac := normaliseMAC(fields[3]); mac != "" {
				return mac
			}
		}
	}
	return ""
}

func lookupMACViaARPCommand(ctx context.Context, host string) string {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "arp", "-a", host)
	} else {
		cmd = exec.CommandContext(ctx, "arp", "-n", host)
	}
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	match := macLinePattern.FindString(string(output))
	return normaliseMAC(match)
}

func lookupManufacturer(mac string) string {
	if mac == "" {
		return ""
	}
	vendor := oui.Vendor(strings.ToLower(mac))
	if vendor != "" {
		return vendor
	}
	return "Unknown"
}
