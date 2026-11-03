package config

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

func ParseTCPAddr(s string, defPort int) (*net.TCPAddr, error) {
	port := defPort
	host := s

	if strings.HasPrefix(s, "[") {
		j := strings.IndexByte(s, ']')
		if j < 0 {
			return nil, fmt.Errorf("missing ]")
		}
		host = s[1:j]
		rest := s[j+1:]
		if rest != "" {
			if !strings.HasPrefix(rest, ":") {
				return nil, fmt.Errorf("bad address")
			}
			p, err := strconv.Atoi(rest[1:])
			if err != nil || p <= 0 || p > 0xffff {
				return nil, fmt.Errorf("bad port")
			}
			port = p
		}
	} else {
		colons := strings.Count(s, ":")
		if colons == 1 {
			i := strings.LastIndexByte(s, ':')
			if i >= 0 && i+1 < len(s) {
				if p, err := strconv.Atoi(s[i+1:]); err == nil {
					if p <= 0 || p > 0xffff {
						return nil, fmt.Errorf("bad port")
					}
					port = p
					host = s[:i]
				}
			}
		} else if colons > 1 {
			i := strings.IndexByte(s, ':')
			if i >= 0 && i+1 < len(s) && s[i+1] >= '0' && s[i+1] <= '9' {
				// C accepts "addr:port" only when the first colon is followed by a digit,
				// which cannot happen in a bare IPv6 literal.
				if p, err := strconv.Atoi(s[i+1:]); err == nil && p > 0 && p <= 0xffff {
					port = p
					host = s[:i]
				}
			}
		}
	}

	zone := ""
	if i := strings.IndexByte(host, '%'); i >= 0 {
		zone = host[i+1:]
		host = host[:i]
	}
	ap, err := netip.ParseAddr(host)
	if err != nil {
		return nil, err
	}
	ip := net.IP(ap.AsSlice())
	return &net.TCPAddr{IP: ip, Port: port, Zone: zone}, nil
}

var schemes = []struct {
	prefix string
	mode   int
}{
	{"socks4://", ModeSocks4},
	{"socks5://", ModeSocks5},
	{"socks://", ModeSocks},
	{"ss://", ModeShadowsocks},
	{"http://", ModeHTTP},
	{"sni://", ModeRawTLS},
	{"tcp://", ModeTCP},
	{"red://", ModeTransparent},
}

func ParseScheme(s string, defPort int) (int, *net.TCPAddr, error) {
	mode := 0
	for _, sc := range schemes {
		if strings.HasPrefix(s, sc.prefix) {
			mode = sc.mode
			s = s[len(sc.prefix):]
			break
		}
	}
	a, err := ParseTCPAddr(s, defPort)
	if err != nil {
		return 0, nil, err
	}
	return mode, a, nil
}

func DefaultTTL() int {
	if v := sysDefaultTTL(); v > 0 {
		return v
	}
	return 64
}

func netTCPAddrV6Zero() *net.TCPAddr {
	return &net.TCPAddr{IP: net.IPv6unspecified}
}
