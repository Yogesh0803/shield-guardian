package traffic

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync"

	"github.com/williamfhe/godivert"
)

// WinDivertFilter is a custom Windows packet filter using WinDivert.
// It intercepts packets at the kernel level and drops those matching
// block rules — completely independent of Windows Defender Firewall.
type WinDivertFilter struct {
	mu          sync.RWMutex
	blockedIPs  map[string]bool
	blockedNets []*net.IPNet
	running     bool
	handle      *godivert.WinDivertHandle
	stats       FilterStats
}

// FilterStats tracks packet filter statistics.
type FilterStats struct {
	TotalInspected uint64
	TotalDropped   uint64
	TotalPassed    uint64
}

// NewWinDivertFilter creates a new custom packet filter instance.
func NewWinDivertFilter() *WinDivertFilter {
	return &WinDivertFilter{
		blockedIPs:  make(map[string]bool),
		blockedNets: make([]*net.IPNet, 0),
	}
}

// Start opens the WinDivert handle and begins filtering packets.
// Must be run with Administrator privileges.
func (f *WinDivertFilter) Start() error {
	f.mu.Lock()
	if f.running {
		f.mu.Unlock()
		return nil
	}
	f.mu.Unlock()

	// Open WinDivert handle capturing all IPv4 traffic
	handle, err := godivert.NewWinDivertHandle("ip")
	if err != nil {
		return fmt.Errorf("failed to open WinDivert handle: %w", err)
	}

	f.mu.Lock()
	f.handle = handle
	f.running = true
	f.stats = FilterStats{}
	f.mu.Unlock()

	go f.filterLoop()
	log.Println("[PacketFilter] Custom WinDivert packet filter started")
	return nil
}

// Stop halts the packet filter.
func (f *WinDivertFilter) Stop() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.running {
		return
	}
	f.running = false
	if f.handle != nil {
		f.handle.Close()
		f.handle = nil
	}
	log.Printf("[PacketFilter] Stopped (inspected=%d, dropped=%d, passed=%d)\n",
		f.stats.TotalInspected, f.stats.TotalDropped, f.stats.TotalPassed)
}

// BlockIP adds an IP address to the block list.
func (f *WinDivertFilter) BlockIP(ip string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.blockedIPs[ip] = true
	log.Printf("[PacketFilter] Blocked IP: %s\n", ip)
}

// UnblockIP removes an IP address from the block list.
func (f *WinDivertFilter) UnblockIP(ip string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.blockedIPs, ip)
	log.Printf("[PacketFilter] Unblocked IP: %s\n", ip)
}

// BlockSubnet adds a CIDR subnet to the block list.
func (f *WinDivertFilter) BlockSubnet(cidr string) error {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR: %w", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.blockedNets = append(f.blockedNets, ipnet)
	log.Printf("[PacketFilter] Blocked subnet: %s\n", cidr)
	return nil
}

// UnblockSubnet removes a CIDR subnet from the block list.
func (f *WinDivertFilter) UnblockSubnet(cidr string) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	filtered := f.blockedNets[:0]
	for _, n := range f.blockedNets {
		if n.String() != ipnet.String() {
			filtered = append(filtered, n)
		}
	}
	f.blockedNets = filtered
	log.Printf("[PacketFilter] Unblocked subnet: %s\n", cidr)
}

// BlockRuleIPs blocks all IPs from a firewall rule config.
func (f *WinDivertFilter) BlockRuleIPs(rule FirewallRule) {
	for _, ip := range rule.BlockedIPs {
		f.BlockIP(ip)
	}
	for _, domain := range rule.BlockedDomains {
		// Resolve domain to IPs and block them
		ips, err := net.LookupHost(domain)
		if err != nil {
			log.Printf("[PacketFilter] Failed to resolve domain %s: %v\n", domain, err)
			continue
		}
		for _, ip := range ips {
			f.BlockIP(ip)
		}
	}
}

// GetStats returns current packet filter statistics.
func (f *WinDivertFilter) GetStats() FilterStats {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.stats
}

// IsRunning returns whether the filter is active.
func (f *WinDivertFilter) IsRunning() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.running
}

// filterLoop is the main packet interception loop.
func (f *WinDivertFilter) filterLoop() {
	defer func() {
		f.mu.Lock()
		f.running = false
		f.mu.Unlock()
	}()

	for {
		f.mu.RLock()
		running := f.running
		handle := f.handle
		f.mu.RUnlock()
		if !running || handle == nil {
			return
		}

		packet, err := handle.Recv()
		if err != nil {
			f.mu.RLock()
			stillRunning := f.running
			f.mu.RUnlock()
			if !stillRunning {
				return
			}
			log.Printf("[PacketFilter] Recv error: %v\n", err)
			continue
		}

		srcIP, dstIP := extractIPs(packet.Raw)

		f.mu.Lock()
		f.stats.TotalInspected++

		drop := f.shouldDrop(srcIP, dstIP)
		if drop {
			f.stats.TotalDropped++
			f.mu.Unlock()
			// Do NOT re-inject — packet is silently dropped
			continue
		}

		f.stats.TotalPassed++
		f.mu.Unlock()

		// Re-inject the packet
		_, err = handle.Send(packet)
		if err != nil {
			f.mu.RLock()
			stillRunning := f.running
			f.mu.RUnlock()
			if !stillRunning {
				return
			}
			log.Printf("[PacketFilter] Send error: %v\n", err)
		}
	}
}

// shouldDrop checks if a packet should be blocked. Caller must hold f.mu.
func (f *WinDivertFilter) shouldDrop(srcIP, dstIP string) bool {
	// Check direct IP blocks
	if f.blockedIPs[srcIP] || f.blockedIPs[dstIP] {
		return true
	}

	// Check subnet blocks
	src := net.ParseIP(srcIP)
	dst := net.ParseIP(dstIP)
	for _, ipnet := range f.blockedNets {
		if (src != nil && ipnet.Contains(src)) || (dst != nil && ipnet.Contains(dst)) {
			return true
		}
	}

	return false
}

// extractIPs parses source and destination IPs from a raw IPv4 packet.
func extractIPs(raw []byte) (string, string) {
	if len(raw) < 20 {
		return "", ""
	}
	// IPv4 header: src at offset 12, dst at offset 16
	srcIP := fmt.Sprintf("%d.%d.%d.%d", raw[12], raw[13], raw[14], raw[15])
	dstIP := fmt.Sprintf("%d.%d.%d.%d", raw[16], raw[17], raw[18], raw[19])
	_ = binary.BigEndian // ensure import is used
	return srcIP, dstIP
}
