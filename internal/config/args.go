package config

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"byedpi/internal/filter"
)

var ErrHelp = errors.New("help requested")
var ErrVersion = errors.New("version requested")

type LogFunc func(level int, format string, args ...any)

type option struct {
	name   string
	short  byte
	hasArg bool
	group  bool
}

var optionList = []option{
	{"daemon", 'D', false, false},
	{"pidfile", 'w', true, false},
	{"no-domain", 'N', false, false},
	{"no-ipv6", 'X', false, false},
	{"no-udp", 'U', false, false},
	{"help", 'h', false, false},
	{"version", 'v', false, false},
	{"ip", 'i', true, false},
	{"port", 'p', true, false},
	{"transparent", 'E', false, false},
	{"conn-ip", 'I', true, false},
	{"buf-size", 'b', true, false},
	{"max-conn", 'c', true, false},
	{"debug", 'x', true, false},
	{"tfo", 'F', false, false},
	{"auto", 'A', true, false},
	{"auto-mode", 'L', true, true},
	{"cache-ttl", 'u', true, true},
	{"tcp-timeout", 'T', true, false},
	{"tls-timeout", 'W', true, false},
	{"copy", 'B', true, true},
	{"cache-file", 'y', true, true},
	{"proto", 'K', true, true},
	{"hosts", 'H', true, true},
	{"pf", 'V', true, true},
	{"round", 'R', true, true},
	{"split", 's', true, true},
	{"disorder", 'd', true, true},
	{"oob", 'o', true, true},
	{"disoob", 'q', true, true},
	{"fake", 'f', true, true},
	{"md5sig", 'S', false, true},
	{"fake-sni", 'n', true, true},
	{"ttl", 't', true, true},
	{"fake-data", 'l', true, true},
	{"fake-offset", 'O', true, true},
	{"fake-tls-mod", 'Q', true, true},
	{"oob-data", 'e', true, true},
	{"mod-http", 'M', true, true},
	{"tlsrec", 'r', true, true},
	{"tlsminor", 'm', true, true},
	{"udp-fake", 'a', true, true},
	{"def-ttl", 'g', true, false},
	{"wait-send", 'Z', false, false},
	{"await-int", 'z', true, false},
	{"drop-sack", 'Y', false, true},
	{"protect-path", 'P', true, false},
	{"ipset", 'j', true, true},
	{"connect-to", 'C', true, true},
	{"rst", '0', false, true},
	{"comment", '#', true, true},
	{"cache-merge", '/', true, false},
}

var longOpts = map[string]*option{}
var shortOpts = map[byte]*option{}

func init() {
	for i := range optionList {
		o := &optionList[i]
		longOpts[o.name] = o
		shortOpts[o.short] = o
	}
}

type token struct {
	name  string
	short string
	val   string
}

func tokenize(args []string) ([]token, error) {
	var out []token
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			for _, rest := range args[i+1:] {
				out = append(out, token{name: "", val: rest})
			}
			break
		}
		if strings.HasPrefix(a, "--") {
			s := a[2:]
			name := s
			val := ""
			has := false
			if j := strings.IndexByte(s, '='); j >= 0 {
				name = s[:j]
				val = s[j+1:]
				has = true
			}
			o, ok := longOpts[name]
			if !ok {
				return nil, fmt.Errorf("unknown option: --%s", name)
			}
			if o.hasArg && !has {
				if i+1 >= len(args) {
					return nil, fmt.Errorf("option --%s requires an argument", name)
				}
				i++
				val = args[i]
			} else if !o.hasArg && has {
				return nil, fmt.Errorf("option --%s takes no argument", name)
			}
			out = append(out, token{name: name, val: val})
			continue
		}
		if len(a) > 1 && a[0] == '-' && a != "-" {
			s := a[1:]
			for k := 0; k < len(s); k++ {
				c := s[k]
				o, ok := shortOpts[c]
				if !ok {
					return nil, fmt.Errorf("unknown option: -%c", c)
				}
				if o.hasArg {
					val := s[k+1:]
					if val == "" {
						if i+1 >= len(args) {
							return nil, fmt.Errorf("option -%c requires an argument", c)
						}
						i++
						val = args[i]
					}
					out = append(out, token{name: o.name, val: val})
					break
				}
				out = append(out, token{name: o.name})
			}
			continue
		}
		out = append(out, token{val: a})
	}
	return out, nil
}

type Parser struct {
	P       *Params
	log     LogFunc
	dp      *DesyncParams
	allLim  bool
	needTTL bool
}

func ParseArgs(args []string, log LogFunc) (*Params, error) {
	p := NewParams()
	ps := &Parser{P: p, log: log, allLim: true}
	ps.dp = p.AddGroup(nil)

	toks, err := tokenize(args)
	if err != nil {
		return nil, err
	}
	for _, t := range toks {
		if t.name == "" {
			return nil, fmt.Errorf("unexpected argument: %s", t.val)
		}
		if err := ps.apply(t.name, t.val); err != nil {
			return nil, err
		}
	}
	if ps.allLim && p.HasFilteredGroups() {
		p.AddGroup(ps.dp)
	}
	if p.Mode == 0 {
		p.Mode = ModeSocks4 | ModeSocks5
	}
	if p.DefTTL == 0 {
		p.DefTTL = DefaultTTL()
	}
	if p.BAddr == nil {
		p.BAddr = netTCPAddrV6Zero()
	}
	return p, nil
}

func (ps *Parser) apply(name, val string) error {
	p := ps.P
	dp := ps.dp

	switch name {
	case "help":
		return ErrHelp
	case "version":
		return ErrVersion
	case "no-domain":
		p.Resolve = false
	case "no-ipv6":
		p.IPv6 = false
	case "no-udp":
		p.UDP = false
	case "daemon":
		p.Daemonize = true
	case "pidfile":
		p.PidFile = val
	case "transparent":
		p.Mode = ModeTransparent
	case "tfo":
		p.TFO = true
	case "md5sig":
		dp.MD5Sig = true
	case "drop-sack":
		dp.DropSack = true
	case "wait-send":
		p.WaitSend = true
	case "rst":
		dp.RST = true
	case "await-int":
		v, err := strconv.Atoi(val)
		if err != nil {
			return err
		}
		p.AwaitInt = v
	case "debug":
		v, err := strconv.Atoi(val)
		if err != nil || v < 0 {
			return fmt.Errorf("invalid debug: %s", val)
		}
		p.Debug = v
	case "ip":
		defPort := 0
		if p.LAddr != nil {
			defPort = p.LAddr.Port
		}
		mode, a, err := ParseScheme(val, defPort)
		if err != nil {
			return fmt.Errorf("invalid ip: %s", val)
		}
		p.LAddr = a
		p.Mode |= mode
	case "port":
		v, err := strconv.Atoi(val)
		if err != nil || v <= 0 || v > 0xffff {
			return fmt.Errorf("invalid port: %s", val)
		}
		if p.LAddr == nil {
			p.LAddr = netTCPAddrV6Zero()
		}
		p.LAddr.Port = v
	case "conn-ip":
		a, err := ParseTCPAddr(val, 0)
		if err != nil {
			return fmt.Errorf("invalid conn-ip: %s", val)
		}
		p.BAddr = a
		if a.IP.To4() != nil {
			p.IPv6 = false
		}
	case "buf-size":
		v, err := strconv.Atoi(val)
		if err != nil || v <= 0 {
			return fmt.Errorf("invalid buf-size: %s", val)
		}
		p.BFSize = v
	case "max-conn":
		v, err := strconv.Atoi(val)
		if err != nil || v <= 0 || v >= 0xffff/2 {
			return fmt.Errorf("invalid max-conn: %s", val)
		}
		p.MaxOpen = v
	case "def-ttl":
		v, err := strconv.Atoi(val)
		if err != nil || v <= 0 || v > 255 {
			return fmt.Errorf("invalid def-ttl: %s", val)
		}
		p.DefTTL = v
		p.CustomTTL = true
	case "protect-path":
		p.ProtectPath = val
	case "cache-merge":
		v, err := strconv.Atoi(val)
		if err != nil || v < 0 || v > 32 {
			return fmt.Errorf("invalid cache-merge: %s", val)
		}
		p.CachePre = 32 - v
	case "tcp-timeout":
		parts := strings.SplitN(val, ":", 2)
		f, err := strconv.ParseFloat(parts[0], 64)
		if err != nil || f < 0 {
			return fmt.Errorf("invalid tcp-timeout: %s", val)
		}
		p.Timeout = uint32(f * 1000)
		if len(parts) == 2 {
			n, err := strconv.ParseFloat(parts[1], 64)
			if err != nil {
				return fmt.Errorf("invalid tcp-timeout: %s", val)
			}
			p.TCPToBytesLim = int(n)
		}
	case "tls-timeout":
		parts := strings.Split(val, ":")
		f, err := strconv.ParseFloat(parts[0], 64)
		if err != nil || f < 0 {
			return fmt.Errorf("invalid tls-timeout: %s", val)
		}
		p.TLSTimeout = uint32(f * 1000)
		if len(parts) > 1 {
			n, _ := strconv.Atoi(parts[1])
			p.TLSToCountLim = n
		}
		if len(parts) > 2 {
			n, _ := strconv.Atoi(parts[2])
			p.TLSToBytesLim = n
		}
	case "auto":
		if !(dp.Hosts != nil || dp.Proto != 0 || dp.PF[0] != 0 || dp.Detect != 0 || dp.IPSet != nil) {
			ps.allLim = false
		}
		ndp := p.AddGroup(dp)
		ndp.Prev = dp
		ps.dp = ndp
		dp = ndp
		if err := parseAuto(dp, val); err != nil {
			return err
		}
		if dp.Detect != 0 {
			p.AutoReconnect = true
		}
	case "auto-mode":
		for _, c := range strings.Split(val, ",") {
			if c == "" {
				continue
			}
			switch c[0] {
			case 'o':
				dp.AutoLevel |= AutoOnReconn
			case 's':
				dp.AutoLevel |= AutoSort
			case 'n':
				dp.AutoLevel |= AutoNoReconn
			default:
				return fmt.Errorf("invalid auto-mode: %s", val)
			}
		}
	case "cache-ttl":
		v, err := strconv.Atoi(val)
		if err != nil || v <= 0 {
			return fmt.Errorf("invalid cache-ttl: %s", val)
		}
		dp.CacheTTL = v
	case "cache-file":
		dp.CacheFile = val
	case "comment":
		dp.Str = val
	case "copy":
		if strings.HasPrefix(val, "i") {
			dp.PF[0] = 1
			break
		}
		v, err := strconv.Atoi(val)
		if err != nil || v <= 0 {
			return fmt.Errorf("invalid copy: %s", val)
		}
		src := p.GroupByID(v - 1)
		if src == nil {
			return fmt.Errorf("invalid copy group: %s", val)
		}
		copyGroup(dp, src)
	case "proto":
		for _, c := range strings.Split(val, ",") {
			if c == "" {
				continue
			}
			switch c[0] {
			case 't':
				dp.Proto |= IsTCP | IsHTTPS
			case 'h':
				dp.Proto |= IsTCP | IsHTTP
			case 'u':
				dp.Proto |= IsUDP
			case 'i':
				dp.Proto |= IsIPv4
			default:
				return fmt.Errorf("invalid proto: %s", val)
			}
		}
	case "hosts":
		if dp.Hosts == nil {
			dp.Hosts = filter.NewHostSet()
		}
		data, err := ReadData(val)
		if err != nil {
			return fmt.Errorf("read hosts: %w", err)
		}
		if err := ParseHosts(dp.Hosts, data, ps.log); err != nil {
			return err
		}
	case "ipset":
		if dp.IPSet == nil {
			dp.IPSet = filter.NewIPSet()
		}
		data, err := ReadData(val)
		if err != nil {
			return fmt.Errorf("read ipset: %w", err)
		}
		if err := ParseIPSet(dp.IPSet, data, ps.log); err != nil {
			return err
		}
	case "pf":
		a, b, err := ParsePortRange(val)
		if err != nil {
			return fmt.Errorf("invalid pf: %s", val)
		}
		dp.PF[0], dp.PF[1] = a, b
	case "round":
		a, b, err := ParseRoundRange(val)
		if err != nil {
			return fmt.Errorf("invalid round: %s", val)
		}
		dp.Rounds[0], dp.Rounds[1] = a, b
	case "split", "disorder", "oob", "disoob", "fake":
		var part Part
		if err := ParseOffset(&part, val); err != nil {
			return fmt.Errorf("invalid %s: %s", name, val)
		}
		switch name {
		case "split":
			part.Mode = DesyncSplit
		case "disorder":
			part.Mode = DesyncDisorder
		case "oob":
			part.Mode = DesyncOOB
		case "disoob":
			part.Mode = DesyncDISOOB
		case "fake":
			part.Mode = DesyncFake
		}
		dp.Parts = append(dp.Parts, part)
	case "ttl":
		v, err := strconv.Atoi(val)
		if err != nil || v <= 0 || v > 255 {
			return fmt.Errorf("invalid ttl: %s", val)
		}
		dp.TTL = v
	case "fake-offset":
		if err := ParseOffset(&dp.FakeOffset, val); err != nil {
			return fmt.Errorf("invalid fake-offset: %s", val)
		}
		dp.FakeOffset.Mode = DesyncSplit
		dp.FakeOffsetSet = true
	case "fake-tls-mod":
		for _, c := range strings.Split(val, ",") {
			if c == "" {
				continue
			}
			switch c[0] {
			case 'r':
				dp.FakeMod |= FMRand
			case 'o':
				dp.FakeMod |= FMOrig
			case 'm':
				i := strings.IndexByte(c, '=')
				if i < 0 {
					return fmt.Errorf("invalid fake-tls-mod: %s", val)
				}
				v, err := strconv.Atoi(c[i+1:])
				if err != nil {
					return fmt.Errorf("invalid fake-tls-mod: %s", val)
				}
				dp.FakeTLSSize = v
			default:
				return fmt.Errorf("invalid fake-tls-mod: %s", val)
			}
		}
	case "fake-sni":
		dp.FakeSNIList = append(dp.FakeSNIList, val)
	case "fake-data":
		if dp.FakeData != nil {
			break
		}
		data, err := ReadData(val)
		if err != nil || len(data) == 0 {
			return fmt.Errorf("read fake-data: %s", val)
		}
		dp.FakeData = data
	case "oob-data":
		d := ParseCForm(val)
		if len(d) != 1 {
			return fmt.Errorf("invalid oob-data: %s", val)
		}
		dp.OOBChar = d[0]
		dp.OOBCharSet = true
	case "mod-http":
		for _, c := range strings.Split(val, ",") {
			if c == "" {
				continue
			}
			switch c[0] {
			case 'r':
				dp.ModHTTP |= MHSpace
			case 'h':
				dp.ModHTTP |= MHHMix
			case 'd':
				dp.ModHTTP |= MHDMix
			default:
				return fmt.Errorf("invalid mod-http: %s", val)
			}
		}
	case "tlsrec":
		var part Part
		if err := ParseOffset(&part, val); err != nil || part.Pos > 0xffff {
			return fmt.Errorf("invalid tlsrec: %s", val)
		}
		dp.TLSRec = append(dp.TLSRec, part)
	case "tlsminor":
		v, err := strconv.Atoi(val)
		if err != nil || v <= 0 || v > 255 {
			return fmt.Errorf("invalid tlsminor: %s", val)
		}
		dp.TLSMinor = v
		dp.TLSMinorSet = true
	case "udp-fake":
		v, err := strconv.Atoi(val)
		if err != nil || v < 0 {
			return fmt.Errorf("invalid udp-fake: %s", val)
		}
		dp.UDPFakeCount = v
	case "connect-to":
		mode, a, err := ParseScheme(val, 0)
		if err != nil {
			return fmt.Errorf("invalid connect-to: %s", val)
		}
		if mode&ModeOutSupport != mode {
			return fmt.Errorf("unsupported connect-to mode: %s", val)
		}
		if mode == 0 {
			mode = ModeSocks5
		}
		dp.OutType = mode
		dp.OutAddr = a
		p.DelayConn = true
	default:
		return fmt.Errorf("unhandled option: %s", name)
	}
	return nil
}

func parseAuto(dp *DesyncParams, val string) error {
	for _, c := range strings.Split(val, ",") {
		if c == "" {
			continue
		}
		switch c[0] {
		case 't':
			dp.Detect |= DetectTorst
		case 'r':
			dp.Detect |= DetectHTTPLocat
		case 's':
			dp.Detect |= DetectTLSErr
		case 'c':
			dp.Detect |= DetectConnect
		case 'n':
		case 'p':
			if strings.HasPrefix(c, "p=") {
				if n, err := strconv.Atoi(c[2:]); err == nil && dp.Prev != nil {
					dp.Prev.Pri = n
				}
			} else {
				return fmt.Errorf("invalid auto: %s", val)
			}
		default:
			return fmt.Errorf("invalid auto: %s", val)
		}
	}
	return nil
}

func copyGroup(dst, src *DesyncParams) {
	dst.TTL = src.TTL
	dst.MD5Sig = src.MD5Sig
	dst.FakeData = src.FakeData
	dst.UDPFakeCount = src.UDPFakeCount
	dst.FakeOffset = src.FakeOffset
	dst.FakeOffsetSet = src.FakeOffsetSet
	dst.FakeSNIList = append([]string(nil), src.FakeSNIList...)
	dst.FakeMod = src.FakeMod
	dst.FakeTLSSize = src.FakeTLSSize
	dst.DropSack = src.DropSack
	dst.OOBChar = src.OOBChar
	dst.OOBCharSet = src.OOBCharSet
	dst.Parts = append([]Part(nil), src.Parts...)
	dst.ModHTTP = src.ModHTTP
	dst.TLSRec = append([]Part(nil), src.TLSRec...)
	dst.TLSMinor = src.TLSMinor
	dst.TLSMinorSet = src.TLSMinorSet
	dst.Proto = src.Proto
	dst.Detect = src.Detect
	dst.AutoLevel = src.AutoLevel
	dst.Hosts = src.Hosts
	dst.IPSet = src.IPSet
	dst.PF = src.PF
	dst.Rounds = src.Rounds
	dst.RST = src.RST
	dst.OutType = src.OutType
	dst.OutAddr = src.OutAddr
	dst.CacheTTL = src.CacheTTL
	dst.CacheFile = src.CacheFile
	dst.Str = src.Str
}
