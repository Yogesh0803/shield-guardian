package traffic

import (
	"fmt"
	"log"
	"os/exec"
	"runtime"
	"strings"
)

// winFilter is a shared WinDivert-based packet filter for Windows.
// Initialized lazily on first use.
var winFilter *WinDivertFilter

// getWinFilter returns (or initializes) the custom WinDivert packet filter.
func getWinFilter() (*WinDivertFilter, error) {
	if winFilter != nil && winFilter.IsRunning() {
		return winFilter, nil
	}
	winFilter = NewWinDivertFilter()
	if err := winFilter.Start(); err != nil {
		return nil, err
	}
	return winFilter, nil
}

// BlockNetworkTraffic blocks all network traffic for the specified applications.
func BlockNetworkTraffic(cfg *Config) {
	for _, rule := range cfg.Firewall.Rules {
		switch runtime.GOOS {
		case "linux", "darwin": // For Linux and macOS
			blockTrafficLinuxMac(rule)
		case "windows":
			blockTrafficWindows(rule)
		default:
			fmt.Printf("OS not supported for blocking network traffic: %s\n", runtime.GOOS)
		}
	}
}

// blockTrafficLinuxMac blocks network traffic using iptables (Linux) or pfctl (macOS).
func blockTrafficLinuxMac(rule FirewallRule) {
	fmt.Printf("Blocking all network traffic for application: %s (ID: %d)\n", rule.Application, rule.ID)

	// Use pgrep to find the process ID(s) of the application
	cmd := exec.Command("pgrep", "-f", rule.Application)
	output, err := cmd.Output()
	if err != nil {
		log.Printf("Failed to find process for application %s: %v", rule.Application, err)
		return
	}

	// Convert output to string and split by lines (in case multiple PIDs are found)
	pids := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(pids) == 0 {
		log.Printf("No processes found for application %s", rule.Application)
		return
	}

	for _, pid := range pids {
		if pid == "" {
			continue
		}

		// Apply iptables rule to drop all traffic for the specific PID
		cmd := exec.Command("sudo", "iptables", "-A", "OUTPUT", "-m", "owner", "--pid-owner", pid, "-j", "DROP")
		if err := cmd.Run(); err != nil {
			log.Printf("Failed to block traffic for application %s (PID: %s) using iptables: %v", rule.Application, pid, err)
		} else {
			fmt.Printf("Successfully blocked traffic for PID: %s (application: %s)\n", pid, rule.Application)
		}
	}
}

// blockTrafficWindows blocks network traffic using the custom WinDivert packet
// filter. Falls back to netsh advfirewall if WinDivert is not available.
func blockTrafficWindows(rule FirewallRule) {
	fmt.Printf("Blocking all network traffic for application: %s (ID: %d)\n", rule.Application, rule.ID)

	// Try the custom WinDivert packet filter first
	pf, err := getWinFilter()
	if err == nil {
		fmt.Printf("[PacketFilter] Using custom WinDivert filter for %s\n", rule.Application)
		pf.BlockRuleIPs(rule)
		return
	}

	// Fallback: Windows Defender Firewall via netsh (legacy behaviour)
	log.Printf("WinDivert unavailable (%v), falling back to netsh for %s", err, rule.Application)
	cmd := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
		"name=BlockTraffic_"+rule.Application,
		"dir=out", "action=block",
		"program=C:\\Path\\To\\"+rule.Application+".exe")
	if err := cmd.Run(); err != nil {
		log.Printf("Failed to block traffic for application %s using netsh: %v", rule.Application, err)
	}
}

// StopWindowsFilter gracefully shuts down the custom packet filter (if running).
func StopWindowsFilter() {
	if winFilter != nil {
		winFilter.Stop()
		winFilter = nil
	}
}
