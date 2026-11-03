package proxy

import (
	"net"
	"sync"
	"time"

	"byedpi/internal/config"
	"byedpi/internal/desync"
	"byedpi/internal/packets"
)

type readResult struct {
	gen  int
	data []byte
	err  error
}

type session struct {
	s      *Server
	client *net.TCPConn
	target *net.TCPAddr

	dp     *config.DesyncParams
	dpMask uint64
	detect int

	round         int
	sentThisRound int
	firstReq      []byte
	firstDone     bool
	detectChecked bool
	host          string
	markTLS       bool
	toCount       int
	dropSack      bool

	remote *net.TCPConn
	gen    int

	events   chan readResult
	stopCh   chan struct{}
	stopOnce sync.Once
}

func (sess *session) log(level int, format string, args ...any) {
	sess.s.log(level, format, args...)
}

func (sess *session) run(initial []byte) {
	sess.events = make(chan readResult, 16)
	sess.stopCh = make(chan struct{})
	defer sess.close()

	sess.startRemote()
	if len(initial) > 0 {
		if !sess.clientData(initial) {
			return
		}
	}
	go sess.readLoop(sess.client, 0)

	for {
		select {
		case ev := <-sess.events:
			if ev.gen == 0 {
				if ev.err != nil {
					return
				}
				if !sess.clientData(ev.data) {
					return
				}
				continue
			}
			if ev.gen != sess.gen {
				continue
			}
			if ev.err != nil {
				if !sess.remoteErr(ev.err) {
					return
				}
				continue
			}
			if !sess.remoteData(ev.data) {
				return
			}
		case <-sess.stopCh:
			return
		}
	}
}

func (sess *session) close() {
	sess.stopOnce.Do(func() {
		close(sess.stopCh)
		if sess.dropSack && sess.remote != nil {
			desync.DetachSack(sess.remote)
		}
		if sess.remote != nil {
			sess.s.track(sess.remote, false)
			sess.remote.Close()
		}
	})
}

func (sess *session) startRemote() {
	sess.gen++
	gen := sess.gen
	c := sess.remote
	go sess.readLoop(c, gen)
}

func (sess *session) readLoop(c net.Conn, gen int) {
	buf := make([]byte, sess.s.Cfg.BFSize)
	for {
		n, err := c.Read(buf)
		if n > 0 {
			data := append([]byte(nil), buf[:n]...)
			select {
			case sess.events <- readResult{gen: gen, data: data}:
			case <-sess.stopCh:
				return
			}
		}
		if err != nil {
			select {
			case sess.events <- readResult{gen: gen, err: err}:
			case <-sess.stopCh:
			}
			return
		}
	}
}

func writeAll(c net.Conn, p []byte) error {
	for len(p) > 0 {
		n, err := c.Write(p)
		if err != nil {
			return err
		}
		if n == 0 {
			return net.ErrClosed
		}
		p = p[n:]
	}
	return nil
}

func (sess *session) clientData(data []byte) bool {
	first := !sess.firstDone
	if first {
		sess.firstDone = true
		if !sess.prepare(data) {
			return false
		}
	}
	if sess.sentThisRound == 0 {
		sess.round++
	}
	if !first && sess.round == 1 && sess.s.Cfg.AutoReconnect &&
		sess.firstReq != nil && len(sess.firstReq) < sess.s.Cfg.BFSize {
		sess.firstReq = append(sess.firstReq, data...)
		if len(sess.firstReq) >= sess.s.Cfg.BFSize {
			sess.firstReq = nil
		}
	}
	if sess.dp == nil {
		return false
	}
	if err := sess.send(data); err != nil {
		sess.log(1, "send: %v\n", err)
		return false
	}
	sess.sentThisRound += len(data)
	if sess.markTLS && sess.round == 1 {
		sess.setTLSDeadline()
	}
	return true
}

func (sess *session) prepare(data []byte) bool {
	sess.firstReq = append([]byte(nil), data...)
	if sess.s.Cfg.AutoReconnect && len(sess.firstReq) >= sess.s.Cfg.BFSize {
		sess.firstReq = nil
	}
	sess.markTLS = packets.IsTLSClientHello(data)
	sess.host = packets.HostString(data)

	dp := sess.s.findDPFrom(sess.dp, sess.target, false, data, sess.dpMask, sess.detect)
	if dp == nil {
		sess.log(1, "drop connection (filter): %s:%d\n", sess.target.IP, sess.target.Port)
		return false
	}
	if dp != sess.dp {
		sess.log(2, "select group: %d -> %d\n", sess.dp.ID, dp.ID)
	}
	sess.dp = dp
	sess.dp.Calls++
	if dp.RST {
		sess.log(1, "drop connection (rst): %s:%d\n", sess.target.IP, sess.target.Port)
		return false
	}

	if sess.s.Cfg.Timeout != 0 {
		desync.SetUserTimeout(sess.remote, sess.s.Cfg.Timeout)
	}
	if dp.DropSack {
		if err := desync.DropSack(sess.remote); err == nil {
			sess.dropSack = true
		}
	}
	return true
}

func (sess *session) send(data []byte) error {
	opts := desync.Options{
		DefaultTTL: sess.s.Cfg.DefTTL,
		WaitSend:   sess.s.Cfg.WaitSend,
		AwaitInt:   sess.s.Cfg.AwaitInt,
		Log:        sess.s.log,
	}
	if sess.dp.RoundAllowed(sess.round) {
		sess.log(2, "desync TCP: group=%d, round=%d, fd=%d\n", sess.dp.ID, sess.round, connFd(sess.remote))
		return desync.Desync(sess.remote, data, sess.dp, opts)
	}
	return writeAll(sess.remote, data)
}

func (sess *session) setTLSDeadline() {
	if sess.s.Cfg.TLSTimeout == 0 {
		return
	}
	sess.remote.SetReadDeadline(time.Now().Add(time.Duration(sess.s.Cfg.TLSTimeout) * time.Millisecond))
}

func (sess *session) remoteData(data []byte) bool {
	sess.sentThisRound = 0
	if sess.dropSack && sess.remote != nil {
		desync.DetachSack(sess.remote)
		sess.dropSack = false
	}
	if sess.markTLS && sess.remote != nil {
		sess.remote.SetReadDeadline(time.Time{})
	}

	if !sess.detectChecked && sess.round <= 1 && len(sess.firstReq) > 0 {
		sess.detectChecked = true
		if sess.markTLS {
			if sess.s.hasDetect(config.DetectTLSErr) &&
				(!packets.IsTLSServerHello(data) || packets.NeqTLSSID(sess.firstReq, data)) {
				if sess.trigger(config.DetectTLSErr) {
					return true
				}
			}
		} else if packets.IsHTTP(sess.firstReq) {
			if sess.s.hasDetect(config.DetectHTTPLocat) && packets.IsHTTPRedirect(sess.firstReq, data) {
				if sess.trigger(config.DetectHTTPLocat) {
					return true
				}
			}
		}
	}

	if err := writeAll(sess.client, data); err != nil {
		return false
	}
	return true
}

func (sess *session) remoteErr(err error) bool {
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		if sess.s.Cfg.TLSToCountLim > 1 && sess.toCount+1 < sess.s.Cfg.TLSToCountLim {
			sess.toCount++
			if sess.remote != nil {
				sess.setTLSDeadline()
				sess.startRemote()
			}
			return true
		}
		return sess.trigger(config.DetectTorst)
	}
	if sess.markTLS && sess.round <= 1 {
		return sess.trigger(config.DetectTLSErr)
	}
	return false
}

func (sess *session) trigger(typ int) bool {
	canReconn := sess.s.Cfg.AutoReconnect && len(sess.firstReq) > 0
	old := sess.dp
	if old == nil {
		return false
	}
	old.FailCount++
	sess.dpMask |= old.Bit
	sess.detect |= typ
	sess.s.Cache.Put(sess.target.IP, sess.target.Port, old, sess.dpMask, sess.detect, sess.host)

	next := sess.s.nextDP(old, sess.target, false, sess.firstReq, sess.dpMask, typ, canReconn)
	if next == nil {
		sess.log(1, "unreach ip: %s\n", sess.target.IP)
		sess.s.Cache.Delete(sess.target.IP, sess.target.Port)
		return false
	}
	sess.s.Cache.Put(sess.target.IP, sess.target.Port, next, sess.dpMask, sess.detect, sess.host)
	if next.AutoLevel&config.AutoNoReconn != 0 || !canReconn {
		return false
	}

	var remote *net.TCPConn
	var err error
	for next != nil {
		remote, err = sess.s.dialTCP(sess.target, next)
		if err == nil {
			break
		}
		sess.log(1, "reconnect: %v\n", err)
		next.FailCount++
		sess.dpMask |= next.Bit
		sess.detect |= config.DetectConnect
		next = sess.s.nextDP(next, sess.target, false, sess.firstReq, sess.dpMask, typ, canReconn)
	}
	if next == nil || remote == nil {
		return false
	}

	sess.gen++
	oldRemote := sess.remote
	sess.remote = nil
	if oldRemote != nil {
		sess.s.track(oldRemote, false)
		oldRemote.Close()
	}

	sess.remote = remote
	sess.s.track(remote, true)
	sess.dp = next
	sess.detectChecked = false
	sess.sentThisRound = 0
	if sess.round < 1 {
		sess.round = 1
	}
	sess.log(2, "reconnect: new group=%d, addr=%s:%d\n", next.ID, sess.target.IP, sess.target.Port)
	sess.startRemote()

	if err := sess.send(sess.firstReq); err != nil {
		sess.log(1, "replay: %v\n", err)
		return false
	}
	sess.sentThisRound += len(sess.firstReq)
	if sess.markTLS {
		sess.setTLSDeadline()
	}
	return true
}
