package desync

import (
	"fmt"
	"math/rand"
	"net"
	"syscall"
	"time"

	"byedpi/internal/config"
	"byedpi/internal/packets"
)

const DefaultTTL = 8

type LogFunc func(level int, format string, args ...any)

type ProtoInfo struct {
	Init    bool
	Type    int
	HostLen int
	HostPos int
}

type Options struct {
	DefaultTTL int
	WaitSend   bool
	AwaitInt   int
	Log        LogFunc
}

func (o Options) log(level int, format string, args ...any) {
	if o.Log != nil {
		o.Log(level, format, args...)
	}
}

func InitProtoInfo(buf []byte, info *ProtoInfo) {
	if info.Init {
		return
	}
	if off, l, ok := packets.ParseTLS(buf); ok {
		info.Type = config.IsHTTPS
		info.HostLen = l
		info.HostPos = off
	} else if off, l, _, ok := packets.ParseHTTP(buf); ok {
		info.Type = config.IsHTTP
		info.HostLen = l
		info.HostPos = off
	}
	info.Init = true
}

func GenOffset(pos int64, flag int, buf []byte, n int, lp int64, info *ProtoInfo) int64 {
	if flag&(config.OffsetSNI|config.OffsetHost) != 0 {
		InitProtoInfo(buf, info)
		if info.HostPos == 0 || (flag&config.OffsetSNI != 0 && info.Type != config.IsHTTPS) {
			return -1
		}
		pos += int64(info.HostPos)
		if flag&config.OffsetEnd != 0 {
			pos += int64(info.HostLen)
		} else if flag&config.OffsetMid != 0 {
			pos += int64(info.HostLen / 2)
		} else if flag&config.OffsetRand != 0 && info.HostLen > 0 {
			pos += int64(rand.Intn(info.HostLen))
		}
	} else if flag&config.OffsetRand != 0 {
		if int64(n) > lp {
			pos += lp + int64(rand.Intn(int(int64(n)-lp)))
		}
	} else if flag&config.OffsetMid != 0 {
		pos += int64(n / 2)
	} else if pos < 0 || flag&config.OffsetEnd != 0 {
		pos += int64(n)
	}
	return pos
}

func sendAll(c net.Conn, p []byte) error {
	for len(p) > 0 {
		n, err := c.Write(p)
		if err != nil {
			return err
		}
		if n == 0 {
			return fmt.Errorf("short write")
		}
		p = p[n:]
	}
	return nil
}

func sendOOBPart(c net.Conn, buf []byte, pos int, dp *config.DesyncParams) (int, error) {
	if len(buf) <= pos {
		return -1, syscall.EINVAL
	}
	ch := byte('a')
	if dp.OOBCharSet {
		ch = dp.OOBChar
	}
	saved := buf[pos]
	buf[pos] = ch
	n, err := sendOOB(c, buf[:pos+1])
	buf[pos] = saved
	if err != nil {
		return -1, err
	}
	n--
	if n != pos {
		return n, nil
	}
	return n, nil
}

func tamp(buf *[]byte, n *int, dp *config.DesyncParams, info *ProtoInfo) {
	b := *buf
	if dp.ModHTTP != 0 && packets.IsHTTP(b[:*n]) {
		packets.ModHTTP(b[:*n], dp.ModHTTP)
	}
	if dp.TLSMinorSet && packets.IsTLSClientHello(b[:*n]) {
		b[2] = byte(dp.TLSMinor)
	}
	if len(dp.TLSRec) != 0 && packets.IsTLSClientHello(b[:*n]) {
		lp := 0
		var part config.Part
		i := 0
		r := 0
		rc := 0
		for r > 0 || i < len(dp.TLSRec) {
			if r <= 0 {
				part = dp.TLSRec[i]
				r = part.Repeats
				if r <= 0 {
					r = 1
				}
				i++
			}
			pos := int64(rc * 5)
			if pos > int64(*n) {
				pos = int64(*n)
			}
			np := int(pos)
			pos += GenOffset(part.Pos, part.Flags, b[:*n-np], *n-np, int64(lp), info)
			if part.Pos < 0 || part.Flags != 0 {
				pos -= 5
			}
			pos += int64(part.Skip * (part.Repeats - r))
			if pos < int64(lp) {
				break
			}
			if *n+5 > len(b) {
				nb := make([]byte, *n+5+4096)
				copy(nb, b[:*n])
				*buf = nb
				b = nb
			}
			got := packets.PartTLS(b[lp:], len(b)-lp, *n-lp, pos-int64(lp))
			if got == 0 {
				break
			}
			*n += 5
			lp = int(pos) + 5
			r--
			rc++
		}
	}
}

// Desync sends the given request using the configured desync methods.
func Desync(c net.Conn, input []byte, dp *config.DesyncParams, opts Options) error {
	n := len(input)
	if n == 0 {
		return nil
	}
	buf := make([]byte, n, n+8192)
	copy(buf, input)
	info := ProtoInfo{}

	if opts.Log != nil {
		InitProtoInfo(buf, &info)
		if info.HostPos != 0 {
			opts.log(2, "host: %s\n", string(buf[info.HostPos:info.HostPos+info.HostLen]))
		} else {
			m := n
			if m > 16 {
				m = 16
			}
			opts.log(2, "bytes: %x (%d)\n", buf[:m], n)
		}
	}

	tamp(&buf, &n, dp, &info)

	lp := 0
	rest := false

	for i := 0; i < len(dp.Parts) && !rest; i++ {
		part := dp.Parts[i]
		rep := part.Repeats
		if rep <= 0 {
			rep = 1
		}
		for k := 0; k < rep; k++ {
			pos := GenOffset(part.Pos, part.Flags, buf, n, int64(lp), &info)
			pos += int64(part.Skip * k)

			if pos < 0 || pos < int64(lp) {
				opts.log(1, "split cancel: pos=%d-%d, n=%d\n", lp, pos, n)
				rest = true
				break
			}
			if pos > int64(n) {
				pos = int64(n)
			}
			seg := buf[lp:pos]

			switch part.Mode {
			case config.DesyncFake:
				fake, off := getTCPFake(buf[:n], &info, dp)
				if fake == nil {
					return fmt.Errorf("fake packet allocation failed")
				}
				sl := int(pos) - lp
				if sl > 0 {
					if err := sendFake(c, fake, off, sl, dp, opts); err != nil {
						return err
					}
				}
			case config.DesyncOOB:
				s, err := sendOOBPart(c, buf[lp:], int(pos)-lp, dp)
				if err != nil {
					return err
				}
				if s != int(pos)-lp {
					return fmt.Errorf("oob short send")
				}
			case config.DesyncDisorder, config.DesyncDISOOB:
				if k%2 == 0 {
					if err := SetTTL(c, 1); err != nil {
						return err
					}
				}
				var err error
				if part.Mode == config.DesyncDISOOB {
					_, err = sendOOBPart(c, buf[lp:], int(pos)-lp, dp)
				} else {
					err = sendAll(c, seg)
				}
				if err != nil {
					return err
				}
				if k%2 == 0 {
					if err := SetTTL(c, opts.DefaultTTL); err != nil {
						return err
					}
				}
			default:
				if err := sendAll(c, seg); err != nil {
					return err
				}
			}
			opts.log(2, "split: pos=%d-%d (%d), m: %s\n", lp, pos, len(seg), part.Mode)
			lp = int(pos)

			if opts.WaitSend {
				if err := waitNotSent(c, opts); err != nil {
					return err
				}
			}
		}
	}

	if lp < n {
		opts.log(2, "send: pos=%d-%d\n", lp, n)
		if err := sendAll(c, buf[lp:n]); err != nil {
			return err
		}
	}
	return nil
}

func waitNotSent(c net.Conn, opts Options) error {
	// Wait for the kernel send queue to drain a little. Short sleep mirrors
	// the await interval used by the C implementation.
	if opts.AwaitInt > 0 {
		time.Sleep(time.Duration(opts.AwaitInt) * time.Millisecond)
	}
	return nil
}

func getTCPFake(buf []byte, info *ProtoInfo, dp *config.DesyncParams) ([]byte, int) {
	var pkt []byte
	if dp.FakeData != nil {
		pkt = dp.FakeData
	} else {
		if !info.Init {
			InitProtoInfo(buf, info)
		}
		if info.Type == config.IsHTTP {
			pkt = fakeHTTP
		} else {
			pkt = fakeTLS
		}
	}
	ps := len(buf)
	if len(pkt) > ps {
		ps = len(pkt)
	}
	out := make([]byte, ps+1024)
	copy(out, pkt)

	sni := ""
	if len(dp.FakeSNIList) > 0 {
		sni = dp.FakeSNIList[rand.Intn(len(dp.FakeSNIList))]
	}
	fSize := dp.FakeTLSSize
	if fSize < 0 {
		fSize = len(buf) + fSize
	}
	if fSize > len(buf) || fSize <= 0 {
		fSize = len(buf)
	}
	if dp.FakeMod&config.FMOrig != 0 && info.Type == config.IsHTTPS {
		copy(out, buf)
		if sni != "" {
			if !packets.ChangeTLSSNI(sni, out, len(pkt), fSize) {
				copy(out, pkt)
			}
		}
	} else if sni != "" {
		if !packets.ChangeTLSSNI(sni, out, len(pkt), fSize) {
			copy(out, pkt)
		}
	}
	if dp.FakeMod&config.FMRand != 0 {
		packets.RandomizeTLS(out, ps)
	}
	off := 0
	if dp.FakeOffsetSet {
		off64 := GenOffset(dp.FakeOffset.Pos, dp.FakeOffset.Flags, buf, len(buf), 0, info)
		if off64 >= 0 && off64 <= int64(len(out)) {
			off = int(off64)
		}
	}
	return out, off
}

func sendFake(c net.Conn, fake []byte, off, pos int, dp *config.DesyncParams, opts Options) error {
	need := off + pos
	if need > len(fake) {
		nb := make([]byte, need)
		copy(nb, fake)
		fake = nb
	}
	ttl := dp.TTL
	if ttl == 0 {
		ttl = DefaultTTL
	}
	if err := SetTTL(c, ttl); err != nil {
		return err
	}
	if dp.MD5Sig {
		SetMD5Sig(c, 5)
	}
	err := sendAll(c, fake[off:off+pos])
	if dp.MD5Sig {
		SetMD5Sig(c, 0)
	}
	if e := SetTTL(c, opts.DefaultTTL); e != nil {
		return e
	}
	return err
}

// DesyncUDP sends fake datagrams before the real one.
func DesyncUDP(c net.Conn, buf []byte, dp *config.DesyncParams, opts Options) error {
	if opts.Log != nil {
		m := len(buf)
		if m > 16 {
			m = 16
		}
		opts.log(2, "bytes: %x (%d)\n", buf[:m], len(buf))
	}
	if dp.UDPFakeCount != 0 {
		pkt := fakeUDP
		if dp.FakeData != nil {
			pkt = dp.FakeData
		}
		if dp.FakeOffsetSet && int(dp.FakeOffset.Pos) < len(pkt) {
			pkt = pkt[dp.FakeOffset.Pos:]
		}
		ttl := dp.TTL
		if ttl == 0 {
			ttl = DefaultTTL
		}
		if err := SetTTL(c, ttl); err != nil {
			return err
		}
		for i := 0; i < dp.UDPFakeCount; i++ {
			if _, err := c.Write(pkt); err != nil {
				return err
			}
		}
		if err := SetTTL(c, opts.DefaultTTL); err != nil {
			return err
		}
	}
	_, err := c.Write(buf)
	return err
}
