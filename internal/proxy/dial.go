package proxy

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"syscall"
	"time"

	"byedpi/internal/config"
	"byedpi/internal/desync"
	"byedpi/internal/packets"
)

func (s *Server) resolveHost(host string, port int) (*net.TCPAddr, error) {
	if ip := net.ParseIP(host); ip != nil {
		return &net.TCPAddr{IP: ip, Port: port}, nil
	}
	if !s.Cfg.Resolve {
		return nil, fmt.Errorf("domain resolving disabled: %s", host)
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}
	var chosen net.IP
	for _, ip := range ips {
		if ip.To4() != nil {
			chosen = ip
			break
		}
	}
	if chosen == nil && s.Cfg.IPv6 {
		for _, ip := range ips {
			chosen = ip
			break
		}
	}
	if chosen == nil {
		return nil, fmt.Errorf("no suitable address for %s", host)
	}
	return &net.TCPAddr{IP: chosen, Port: port}, nil
}

func (s *Server) localAddrFor(dst *net.TCPAddr) net.Addr {
	b := s.Cfg.BAddr
	if b == nil || b.IP == nil || b.IP.IsUnspecified() {
		return nil
	}
	dstV4 := dst.IP.To4() != nil
	bV4 := b.IP.To4() != nil
	if dstV4 != bV4 {
		return nil
	}
	return &net.TCPAddr{IP: b.IP, Port: b.Port, Zone: b.Zone}
}

func (s *Server) dialTCP(target *net.TCPAddr, dp *config.DesyncParams) (*net.TCPConn, error) {
	dest := target
	viaSocks := false

	if dp != nil && dp.OutType != 0 && dp.OutAddr != nil {
		switch dp.OutType {
		case config.ModeSocks5:
			dest = dp.OutAddr
			viaSocks = true
		case config.ModeTCP:
			out := &net.TCPAddr{IP: dp.OutAddr.IP, Port: dp.OutAddr.Port, Zone: dp.OutAddr.Zone}
			if out.Port == 0 {
				out.Port = target.Port
			}
			dest = out
		}
	}

	d := net.Dialer{}
	d.LocalAddr = s.localAddrFor(dest)
	d.Control = func(network, address string, rc syscall.RawConn) error {
		var inner error
		err := rc.Control(func(fd uintptr) {
			ttl := 0
			if s.Cfg.CustomTTL {
				ttl = s.Cfg.DefTTL
			}
			desync.ConfigureDialSocket(fd, ttl, s.Cfg.TFO)
			if s.Cfg.ProtectPath != "" {
				if err := protectFd(fd, s.Cfg.ProtectPath); err != nil {
					inner = err
				}
			}
		})
		if err != nil {
			return err
		}
		return inner
	}

	conn, err := d.Dial("tcp", dest.String())
	if err != nil {
		return nil, err
	}
	tc := conn.(*net.TCPConn)
	tc.SetNoDelay(true)
	if viaSocks {
		if err := socks5Connect(tc, target); err != nil {
			tc.Close()
			return nil, err
		}
	}
	return tc, nil
}

func socks5Connect(c net.Conn, target *net.TCPAddr) error {
	c.SetDeadline(time.Now().Add(10 * time.Second))
	defer c.SetDeadline(time.Time{})
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		return err
	}
	rep := make([]byte, 2)
	if _, err := io.ReadFull(c, rep); err != nil {
		return err
	}
	if rep[0] != 5 || rep[1] != 0 {
		return fmt.Errorf("socks5 auth failed")
	}
	req := []byte{5, 1, 0}
	if v4 := target.IP.To4(); v4 != nil {
		req = append(req, 1)
		req = append(req, v4...)
	} else {
		req = append(req, 4)
		req = append(req, target.IP.To16()...)
	}
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], uint16(target.Port))
	req = append(req, p[:]...)
	if _, err := c.Write(req); err != nil {
		return err
	}
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return err
	}
	if hdr[0] != 5 || hdr[1] != 0 {
		return fmt.Errorf("socks5 connect failed: %d", hdr[1])
	}
	var n int
	switch hdr[3] {
	case 1:
		n = 4 + 2
	case 4:
		n = 16 + 2
	case 3:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return err
		}
		n = int(l[0]) + 2
	default:
		return fmt.Errorf("socks5 bad address type")
	}
	_, err := io.CopyN(io.Discard, c, int64(n))
	return err
}

func checkL34(dp *config.DesyncParams, target *net.TCPAddr, udp bool) bool {
	if dp.Proto&config.IsUDP != 0 && !udp {
		return false
	}
	if dp.Proto&config.IsTCP != 0 && udp {
		return false
	}
	if dp.Proto&config.IsIPv4 != 0 && target.IP.To4() == nil {
		return false
	}
	if dp.PF[0] != 0 {
		p := uint16(target.Port)
		if p < dp.PF[0] || p > dp.PF[1] {
			return false
		}
	}
	if dp.IPSet != nil && !dp.IPSet.Match(target.IP) {
		return false
	}
	return true
}

func checkProtoTCP(proto int, buf []byte) bool {
	if proto == 0 {
		return true
	}
	if proto&^config.IsIPv4 == 0 {
		return true
	}
	if proto&config.IsHTTP != 0 && packets.IsHTTP(buf) {
		return true
	}
	if proto&config.IsHTTPS != 0 && packets.IsTLSClientHello(buf) {
		return true
	}
	return false
}

func checkHost(dp *config.DesyncParams, buf []byte) bool {
	if dp.Hosts == nil {
		return true
	}
	h := packets.HostString(buf)
	if h == "" {
		return false
	}
	return dp.Hosts.Match(h)
}

func (s *Server) hasDetect(typ int) bool {
	for _, dp := range s.Cfg.DP {
		if dp.Detect&typ != 0 {
			return true
		}
	}
	return false
}

func (s *Server) dpIndex(dp *config.DesyncParams) int {
	if dp == nil {
		return 0
	}
	for i, d := range s.Cfg.DP {
		if d == dp {
			return i
		}
	}
	return 0
}

func (s *Server) findDP(start *config.DesyncParams, target *net.TCPAddr, udp bool, buf []byte, detect int) *config.DesyncParams {
	n := len(s.Cfg.DP)
	if n == 0 {
		return nil
	}
	idx := s.dpIndex(start)
	for k := 0; k < n; k++ {
		dp := s.Cfg.DP[(idx+k)%n]
		if dp.Detect != 0 && dp.Detect&detect == 0 && dp != start && !(start == nil && k == 0) {
			continue
		}
		if !checkL34(dp, target, udp) {
			continue
		}
		if buf != nil {
			if dp.Proto != 0 && !checkProtoTCP(dp.Proto, buf) {
				continue
			}
			if dp.Hosts != nil && !checkHost(dp, buf) {
				continue
			}
		}
		return dp
	}
	return nil
}

func (s *Server) nextDP(cur *config.DesyncParams, target *net.TCPAddr, udp bool,
	buf []byte, mask uint64, detect int, canReconn bool) *config.DesyncParams {
	n := len(s.Cfg.DP)
	if n == 0 {
		return nil
	}
	start := s.dpIndex(cur)
	for k := 1; k <= n; k++ {
		dp := s.Cfg.DP[(start+k)%n]
		if dp.Bit&mask != 0 {
			continue
		}
		if dp.Detect != 0 && dp.Detect&detect == 0 {
			continue
		}
		if dp.AutoLevel&config.AutoOnReconn != 0 && !canReconn {
			continue
		}
		if !checkL34(dp, target, udp) {
			continue
		}
		if buf != nil {
			if dp.Proto != 0 && !checkProtoTCP(dp.Proto, buf) {
				continue
			}
			if dp.Hosts != nil && !checkHost(dp, buf) {
				continue
			}
		}
		return dp
	}
	return nil
}

func (s *Server) connectWithFallback(target *net.TCPAddr, start *config.DesyncParams, canReconn bool) (*net.TCPConn, *config.DesyncParams, error) {
	dp := start
	mask := uint64(0)
	detect := 0
	var lastErr error
	for dp != nil {
		conn, err := s.dialTCP(target, dp)
		if err == nil {
			return conn, dp, nil
		}
		lastErr = err
		dp.FailCount++
		mask |= dp.Bit
		detect |= config.DetectConnect
		dp = s.nextDP(dp, target, false, nil, mask, config.DetectConnect, canReconn)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no matching desync group")
	}
	return nil, nil, lastErr
}

func (s *Server) findDPFrom(start *config.DesyncParams, target *net.TCPAddr, udp bool, buf []byte, mask uint64, detect int) *config.DesyncParams {
	n := len(s.Cfg.DP)
	if n == 0 {
		return nil
	}
	idx := s.dpIndex(start)
	for k := 0; k < n; k++ {
		dp := s.Cfg.DP[(idx+k)%n]
		if dp.Bit&mask != 0 {
			continue
		}
		if dp.Detect != 0 && dp.Detect&detect == 0 && dp != start && !(start == nil && k == 0) {
			continue
		}
		if !checkL34(dp, target, udp) {
			continue
		}
		if buf != nil {
			if dp.Proto != 0 && !checkProtoTCP(dp.Proto, buf) {
				continue
			}
			if dp.Hosts != nil && !checkHost(dp, buf) {
				continue
			}
		}
		return dp
	}
	return nil
}
