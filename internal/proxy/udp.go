package proxy

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"
	"sync"

	"byedpi/internal/config"
	"byedpi/internal/desync"
)

func (s *Server) serveUDP(c *net.TCPConn, br *bufio.Reader, req *clientRequest) {
	localIP := net.IPv4zero
	if la, ok := c.LocalAddr().(*net.TCPAddr); ok {
		localIP = la.IP
	}
	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: localIP})
	if err != nil {
		s.log(1, "udp listen: %v\n", err)
		c.Write(socks5Reply(1, nil, 0))
		return
	}
	defer relay.Close()

	ra := relay.LocalAddr().(*net.UDPAddr)
	if _, err := c.Write(socks5Reply(0, ra.IP, ra.Port)); err != nil {
		return
	}

	remote, err := net.ListenUDP("udp", &net.UDPAddr{IP: s.Cfg.BAddr.IP})
	if err != nil {
		s.log(1, "udp remote socket: %v\n", err)
		return
	}
	defer remote.Close()

	var (
		mu         sync.Mutex
		clientAddr *net.UDPAddr
	)
	if req.udpFrom != nil && !req.udpFrom.IP.IsUnspecified() && req.udpFrom.Port != 0 {
		clientAddr = &net.UDPAddr{IP: req.udpFrom.IP, Port: req.udpFrom.Port}
	}

	done := make(chan struct{})
	var once sync.Once
	stop := func() { once.Do(func() { close(done) }) }

	go func() {
		io.Copy(io.Discard, c)
		stop()
	}()

	go func() {
		buf := make([]byte, 65535)
		for {
			n, src, err := remote.ReadFromUDP(buf)
			if err != nil {
				return
			}
			mu.Lock()
			dst := clientAddr
			mu.Unlock()
			if dst == nil {
				continue
			}
			out := make([]byte, 0, n+22)
			out = append(out, 0, 0, 0)
			out = appendSocksAddr(out, src)
			out = append(out, buf[:n]...)
			relay.WriteToUDP(out, dst)
		}
	}()

	go func() {
		<-done
		relay.Close()
		remote.Close()
	}()

	buf := make([]byte, 65535)
	udpRound := 0
	for {
		n, src, err := relay.ReadFromUDP(buf)
		if err != nil {
			return
		}
		payload, dest, err := parseSocksUDP(buf[:n])
		if err != nil || dest == nil {
			continue
		}
		mu.Lock()
		clientAddr = src
		mu.Unlock()

		_ = br
		if udpRound == 0 {
			udpRound = 1
			dp := s.findDP(nil, &net.TCPAddr{IP: dest.IP, Port: dest.Port}, true, nil, 0)
			if dp != nil && dp.RoundAllowed(1) {
				s.sendUDP(remote, payload, dest, dp)
				continue
			}
		}
		remote.WriteToUDP(payload, dest)
	}
}

func (s *Server) sendUDP(remote *net.UDPConn, payload []byte, dest *net.UDPAddr, dp *config.DesyncParams) {
	if dp.UDPFakeCount != 0 {
		pkt := desync.FakeUDP()
		if dp.FakeData != nil {
			pkt = dp.FakeData
		}
		if dp.FakeOffsetSet && int(dp.FakeOffset.Pos) < len(pkt) {
			pkt = pkt[dp.FakeOffset.Pos:]
		}
		ttl := dp.TTL
		if ttl == 0 {
			ttl = desync.DefaultTTL
		}
		if err := desync.SetTTL(remote, ttl); err != nil {
			s.log(1, "udp setttl: %v\n", err)
		}
		for i := 0; i < dp.UDPFakeCount; i++ {
			remote.WriteToUDP(pkt, dest)
		}
		if err := desync.SetTTL(remote, s.Cfg.DefTTL); err != nil {
			s.log(1, "udp setttl: %v\n", err)
		}
	}
	remote.WriteToUDP(payload, dest)
}

func parseSocksUDP(b []byte) ([]byte, *net.UDPAddr, error) {
	if len(b) < 4 {
		return nil, nil, io.ErrUnexpectedEOF
	}
	if b[2] != 0 {
		return nil, nil, io.ErrUnexpectedEOF
	}
	atyp := b[3]
	off := 4
	var ip net.IP
	switch atyp {
	case 1:
		if len(b) < off+4+2 {
			return nil, nil, io.ErrUnexpectedEOF
		}
		ip = net.IPv4(b[off], b[off+1], b[off+2], b[off+3])
		off += 4
	case 4:
		if len(b) < off+16+2 {
			return nil, nil, io.ErrUnexpectedEOF
		}
		ip = make(net.IP, 16)
		copy(ip, b[off:off+16])
		off += 16
	case 3:
		if len(b) < off+1 {
			return nil, nil, io.ErrUnexpectedEOF
		}
		l := int(b[off])
		off++
		if len(b) < off+l+2 {
			return nil, nil, io.ErrUnexpectedEOF
		}
		host := string(b[off : off+l])
		off += l
		port := int(binary.BigEndian.Uint16(b[off:]))
		ip = net.ParseIP(host)
		if ip == nil {
			addrs, err := net.LookupIP(host)
			if err != nil || len(addrs) == 0 {
				return nil, nil, io.ErrUnexpectedEOF
			}
			ip = addrs[0]
		}
		return b[off+2:], &net.UDPAddr{IP: ip, Port: port}, nil
	default:
		return nil, nil, io.ErrUnexpectedEOF
	}
	port := int(binary.BigEndian.Uint16(b[off:]))
	off += 2
	return b[off:], &net.UDPAddr{IP: ip, Port: port}, nil
}

func appendSocksAddr(out []byte, addr *net.UDPAddr) []byte {
	if v4 := addr.IP.To4(); v4 != nil {
		out = append(out, 1)
		out = append(out, v4...)
	} else {
		out = append(out, 4)
		out = append(out, addr.IP.To16()...)
	}
	out = append(out, byte(addr.Port>>8), byte(addr.Port))
	return out
}
