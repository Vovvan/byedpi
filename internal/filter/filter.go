package filter

import (
	"net"
	"strings"
)

type HostSet struct {
	m map[string]struct{}
}

func NewHostSet() *HostSet {
	return &HostSet{m: make(map[string]struct{})}
}

func (h *HostSet) Add(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}
	for _, c := range host {
		if !(c == '-' || c == '.' || c == '_' ||
			(c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	h.m[strings.TrimSuffix(host, ".")] = struct{}{}
	return true
}

func (h *HostSet) Match(host string) bool {
	if h == nil || len(h.m) == 0 {
		return false
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for p := range h.m {
		if host == p || strings.HasSuffix(host, "."+p) {
			return true
		}
	}
	return false
}

func (h *HostSet) Len() int {
	if h == nil {
		return 0
	}
	return len(h.m)
}

type IPSet struct {
	nets []*net.IPNet
}

func NewIPSet() *IPSet { return &IPSet{} }

func (s *IPSet) Add(cidr string) bool {
	cidr = strings.TrimSpace(cidr)
	if cidr == "" {
		return false
	}
	if !strings.Contains(cidr, "/") {
		ip := net.ParseIP(cidr)
		if ip == nil {
			return false
		}
		if v4 := ip.To4(); v4 != nil {
			cidr = v4.String() + "/32"
		} else {
			cidr += "/128"
		}
	}
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	s.nets = append(s.nets, n)
	return true
}

func (s *IPSet) Match(ip net.IP) bool {
	if s == nil {
		return false
	}
	for _, n := range s.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (s *IPSet) Len() int {
	if s == nil {
		return 0
	}
	return len(s.nets)
}
