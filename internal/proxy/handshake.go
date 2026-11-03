package proxy

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"syscall"

	"byedpi/internal/config"
	"byedpi/internal/desync"
	"byedpi/internal/packets"
)

type clientRequest struct {
	target  *net.TCPAddr
	initial []byte
	success func() error
	failure func(error)
	udp     bool
	udpFrom *net.TCPAddr
}

func (s *Server) handle(c *net.TCPConn) {
	s.track(c, true)
	defer func() {
		s.track(c, false)
		c.Close()
	}()
	br := bufio.NewReaderSize(c, maxInt(4096, s.Cfg.BFSize))

	req, err := s.handshake(c, br)
	if err != nil {
		s.log(1, "handshake: %v\n", err)
		return
	}
	if req.udp {
		s.serveUDP(c, br, req)
		return
	}

	start, mask, detect := s.initialDP(req.target)
	remote, dp, err := s.connectWithFallback(req.target, start, true)
	if err != nil {
		s.log(1, "connect: %v\n", err)
		if req.failure != nil {
			req.failure(err)
		}
		return
	}
	if req.success != nil {
		if err := req.success(); err != nil {
			remote.Close()
			return
		}
	}
	s.log(2, "new conn: fd=%d, addr=%s:%d\n", connFd(remote), req.target.IP, req.target.Port)

	sess := &session{
		s:      s,
		client: c,
		target: req.target,
		dp:     dp,
		dpMask: mask,
		detect: detect,
		remote: remote,
	}
	s.track(remote, true)
	sess.run(req.initial)
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func connFd(c net.Conn) int {
	sc, ok := c.(syscall.Conn)
	if !ok {
		return -1
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return -1
	}
	fd := -1
	rc.Control(func(f uintptr) { fd = int(f) })
	return fd
}

func drainBuffered(br *bufio.Reader) []byte {
	n := br.Buffered()
	if n <= 0 {
		return nil
	}
	b, _ := br.Peek(n)
	out := append([]byte(nil), b...)
	br.Discard(n)
	return out
}

func (s *Server) handshake(c *net.TCPConn, br *bufio.Reader) (*clientRequest, error) {
	if s.Cfg.Mode&config.ModeTransparent != 0 {
		if dst, err := desync.GetOriginalDst(c); err == nil && dst != nil {
			return &clientRequest{target: dst}, nil
		} else if s.Cfg.Mode&^config.ModeTransparent == 0 {
			return nil, fmt.Errorf("transparent: %v", err)
		}
	}

	first, err := br.Peek(1)
	if err != nil {
		return nil, err
	}
	if first[0] == 5 && s.Cfg.Mode&config.ModeSocks5 != 0 {
		return s.socks5Handshake(c, br)
	}
	if first[0] == 4 && s.Cfg.Mode&config.ModeSocks4 != 0 {
		return s.socks4Handshake(c, br)
	}
	if s.Cfg.Mode&config.ModeHTTP != 0 {
		p, _ := br.Peek(7)
		if len(p) >= 7 && bytes.HasPrefix(p, []byte("CONNECT")) {
			return s.httpConnect(c, br)
		}
	}
	if s.Cfg.Mode&config.ModeShadowsocks != 0 && first[0] <= 4 {
		return s.shadowsocksHandshake(br)
	}
	if s.Cfg.Mode&config.ModeRawTLS != 0 {
		data, err := s.readInitialTLS(br)
		if err != nil {
			return nil, err
		}
		hostOff, hostLen, ok := packets.ParseTLS(data)
		if !ok {
			return nil, fmt.Errorf("not a TLS ClientHello")
		}
		target, err := s.resolveHost(string(data[hostOff:hostOff+hostLen]), 443)
		if err != nil {
			return nil, err
		}
		return &clientRequest{target: target, initial: data}, nil
	}
	if s.Cfg.Mode&config.ModeTCP != 0 {
		data, err := s.readInitial(br)
		if err != nil {
			return nil, err
		}
		var target *net.TCPAddr
		for _, dp := range s.Cfg.DP {
			if dp.OutAddr != nil {
				target = &net.TCPAddr{IP: dp.OutAddr.IP, Port: dp.OutAddr.Port, Zone: dp.OutAddr.Zone}
				break
			}
		}
		if target == nil {
			return nil, fmt.Errorf("tcp mode requires --connect-to")
		}
		return &clientRequest{target: target, initial: data}, nil
	}
	return nil, fmt.Errorf("invalid request version: 0x%x", first[0])
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (s *Server) readInitial(br *bufio.Reader) ([]byte, error) {
	buf := make([]byte, s.Cfg.BFSize)
	n, err := br.Read(buf)
	if n == 0 {
		if err == nil {
			err = io.EOF
		}
		return nil, err
	}
	out := append([]byte(nil), buf[:n]...)
	return append(out, drainBuffered(br)...), nil
}

func (s *Server) readInitialTLS(br *bufio.Reader) ([]byte, error) {
	data, err := s.readInitial(br)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, s.Cfg.BFSize)
	for !packets.IsTLSClientHello(data) && len(data) < 32768 {
		m, err := br.Read(buf)
		if m > 0 {
			data = append(data, buf[:m]...)
		}
		if err != nil {
			break
		}
	}
	return data, nil
}

func readSocksAddr(br *bufio.Reader, atyp byte, s *Server) (*net.TCPAddr, error) {
	switch atyp {
	case 1:
		b := make([]byte, 6)
		if _, err := io.ReadFull(br, b); err != nil {
			return nil, err
		}
		return &net.TCPAddr{IP: net.IPv4(b[0], b[1], b[2], b[3]), Port: int(binary.BigEndian.Uint16(b[4:]))}, nil
	case 4:
		b := make([]byte, 18)
		if _, err := io.ReadFull(br, b); err != nil {
			return nil, err
		}
		ip := make(net.IP, 16)
		copy(ip, b[:16])
		return &net.TCPAddr{IP: ip, Port: int(binary.BigEndian.Uint16(b[16:]))}, nil
	case 3:
		l, err := br.ReadByte()
		if err != nil {
			return nil, err
		}
		b := make([]byte, int(l)+2)
		if _, err := io.ReadFull(br, b); err != nil {
			return nil, err
		}
		return s.resolveHost(string(b[:l]), int(binary.BigEndian.Uint16(b[l:])))
	default:
		return nil, fmt.Errorf("bad address type: %d", atyp)
	}
}

func (s *Server) socks5Handshake(c *net.TCPConn, br *bufio.Reader) (*clientRequest, error) {
	ver, err := br.ReadByte()
	if err != nil || ver != 5 {
		return nil, fmt.Errorf("bad socks version")
	}
	nm, err := br.ReadByte()
	if err != nil {
		return nil, err
	}
	methods := make([]byte, int(nm))
	if _, err := io.ReadFull(br, methods); err != nil {
		return nil, err
	}
	auth := false
	for _, m := range methods {
		if m == 0 {
			auth = true
			break
		}
	}
	if !auth {
		c.Write([]byte{5, 0xff})
		return nil, fmt.Errorf("no acceptable auth method")
	}
	if _, err := c.Write([]byte{5, 0}); err != nil {
		return nil, err
	}
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return nil, err
	}
	if hdr[0] != 5 {
		return nil, fmt.Errorf("bad request version")
	}
	target, err := readSocksAddr(br, hdr[3], s)
	if err != nil {
		return nil, err
	}
	switch hdr[1] {
	case 1:
		return &clientRequest{
			target:  target,
			initial: drainBuffered(br),
			success: func() error {
				_, err := c.Write(socks5Reply(0, nil, 0))
				return err
			},
			failure: func(err error) {
				code := byte(1)
				if opErr, ok := err.(*net.OpError); ok {
					if strings.Contains(opErr.Err.Error(), "refused") {
						code = 5
					}
				}
				c.Write(socks5Reply(code, nil, 0))
			},
		}, nil
	case 3:
		if !s.Cfg.UDP {
			c.Write(socks5Reply(7, nil, 0))
			return nil, fmt.Errorf("UDP disabled")
		}
		return &clientRequest{target: target, udp: true, udpFrom: target}, nil
	default:
		c.Write(socks5Reply(7, nil, 0))
		return nil, fmt.Errorf("unsupported command: %d", hdr[1])
	}
}

func socks5Reply(code byte, ip net.IP, port int) []byte {
	out := []byte{5, code, 0}
	if ip != nil && ip.To4() == nil {
		out = append(out, 4)
		out = append(out, ip.To16()...)
	} else {
		out = append(out, 1)
		if ip != nil {
			out = append(out, ip.To4()...)
		} else {
			out = append(out, 0, 0, 0, 0)
		}
	}
	out = append(out, byte(port>>8), byte(port))
	return out
}

func (s *Server) socks4Handshake(c *net.TCPConn, br *bufio.Reader) (*clientRequest, error) {
	hdr := make([]byte, 8)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return nil, err
	}
	if hdr[0] != 4 || hdr[1] != 1 {
		return nil, fmt.Errorf("bad socks4 request")
	}
	port := int(binary.BigEndian.Uint16(hdr[2:]))
	user, err := br.ReadString(0)
	if err != nil {
		return nil, err
	}
	_ = user
	var target *net.TCPAddr
	if hdr[4] == 0 && hdr[5] == 0 && hdr[6] == 0 {
		host, err := br.ReadString(0)
		if err != nil {
			return nil, err
		}
		host = strings.TrimSuffix(host, "\x00")
		target, err = s.resolveHost(host, port)
		if err != nil {
			return nil, err
		}
	} else {
		target = &net.TCPAddr{IP: net.IPv4(hdr[4], hdr[5], hdr[6], hdr[7]), Port: port}
	}
	reply := func(ok bool) error {
		b := []byte{0, 0x5b, 0, 0, 0, 0, 0, 0}
		if ok {
			b[1] = 0x5a
		}
		_, err := c.Write(b)
		return err
	}
	return &clientRequest{
		target:  target,
		initial: drainBuffered(br),
		success: func() error { return reply(true) },
		failure: func(error) { reply(false) },
	}, nil
}

func readHTTPHeader(br *bufio.Reader) ([]byte, error) {
	var out []byte
	buf := make([]byte, 1)
	for len(out) < 65536 {
		n, err := br.Read(buf)
		if n > 0 {
			out = append(out, buf[0])
			if len(out) >= 4 && bytes.HasSuffix(out, []byte("\r\n\r\n")) {
				return out, nil
			}
		}
		if err != nil {
			return nil, err
		}
	}
	return nil, fmt.Errorf("HTTP header too large")
}

func splitHostPortDefault(s string, defPort int) (string, int, error) {
	if strings.HasPrefix(s, "[") {
		h, p, err := net.SplitHostPort(s)
		if err != nil {
			return "", 0, err
		}
		n, err := strconv.Atoi(p)
		if err != nil || n <= 0 || n > 0xffff {
			return "", 0, fmt.Errorf("bad port")
		}
		return h, n, nil
	}
	if strings.Count(s, ":") == 1 {
		h, p, err := net.SplitHostPort(s)
		if err == nil {
			n, err := strconv.Atoi(p)
			if err != nil || n <= 0 || n > 0xffff {
				return "", 0, fmt.Errorf("bad port")
			}
			return h, n, nil
		}
	}
	return s, defPort, nil
}

func (s *Server) httpConnect(c *net.TCPConn, br *bufio.Reader) (*clientRequest, error) {
	hdr, err := readHTTPHeader(br)
	if err != nil {
		return nil, err
	}
	lineEnd := bytes.IndexByte(hdr, '\n')
	if lineEnd < 0 {
		return nil, fmt.Errorf("bad HTTP request")
	}
	line := strings.TrimRight(string(hdr[:lineEnd]), "\r")
	fields := strings.Fields(line)
	if len(fields) < 2 || fields[0] != "CONNECT" {
		return nil, fmt.Errorf("unsupported HTTP method")
	}
	host, port, err := splitHostPortDefault(fields[1], 443)
	if err != nil {
		return nil, err
	}
	target, err := s.resolveHost(host, port)
	if err != nil {
		return nil, err
	}
	return &clientRequest{
		target:  target,
		initial: drainBuffered(br),
		success: func() error {
			_, err := c.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
			return err
		},
		failure: func(error) {
			c.Write([]byte("HTTP/1.1 503 Fail\r\n\r\n"))
		},
	}, nil
}

func (s *Server) shadowsocksHandshake(br *bufio.Reader) (*clientRequest, error) {
	atyp, err := br.ReadByte()
	if err != nil {
		return nil, err
	}
	target, err := readSocksAddr(br, atyp, s)
	if err != nil {
		return nil, err
	}
	return &clientRequest{target: target, initial: drainBuffered(br)}, nil
}

func (s *Server) initialDP(target *net.TCPAddr) (*config.DesyncParams, uint64, int) {
	if e := s.Cache.Get(target.IP, target.Port); e != nil && e.DP != nil {
		return e.DP, e.Mask, e.Detect
	}
	return s.findDP(nil, target, false, nil, 0), 0, 0
}
