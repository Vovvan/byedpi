package config

import (
	"net"
	"time"

	"byedpi/internal/filter"
)

type DesyncMode int

const (
	DesyncNone DesyncMode = iota
	DesyncSplit
	DesyncDisorder
	DesyncOOB
	DesyncDISOOB
	DesyncFake
)

func (m DesyncMode) String() string {
	switch m {
	case DesyncSplit:
		return "DESYNC_SPLIT"
	case DesyncDisorder:
		return "DESYNC_DISORDER"
	case DesyncOOB:
		return "DESYNC_OOB"
	case DesyncDISOOB:
		return "DESYNC_DISOOB"
	case DesyncFake:
		return "DESYNC_FAKE"
	default:
		return "DESYNC_NONE"
	}
}

const (
	OffsetEnd   = 1
	OffsetMid   = 2
	OffsetRand  = 4
	OffsetSNI   = 8
	OffsetHost  = 16
	OffsetStart = 32
)

const (
	DetectHTTPLocat = 1
	DetectTLSErr    = 2
	DetectTorst     = 8
	DetectConnect   = 16
)

const (
	AutoOnReconn = 1
	AutoNoReconn = 2
	AutoSort     = 4
)

const (
	ModeSocks5      = 1
	ModeSocks4      = 2
	ModeHTTP        = 4
	ModeTransparent = 8
	ModeShadowsocks = 16
	ModeRawTLS      = 32
	ModeTCP         = 64
	ModeSocks       = ModeSocks4 | ModeSocks5
	ModeOutSupport  = ModeSocks5 | ModeTCP
)

const (
	FMRand = 1
	FMOrig = 2
)

const (
	MHHMix  = 1
	MHSpace = 2
	MHDMix  = 4
)

const (
	IsTCP   = 1
	IsUDP   = 2
	IsHTTP  = 4
	IsHTTPS = 8
	IsIPv4  = 16
)

type Part struct {
	Mode    DesyncMode
	Flags   int
	Pos     int64
	Repeats int
	Skip    int
}

type DesyncParams struct {
	TTL int

	MD5Sig bool

	FakeData []byte

	UDPFakeCount int

	FakeOffset    Part
	FakeOffsetSet bool

	FakeSNIList []string
	FakeMod     int
	FakeTLSSize int

	DropSack bool

	OOBChar    byte
	OOBCharSet bool

	Parts []Part

	ModHTTP int

	TLSRec      []Part
	TLSMinor    int
	TLSMinorSet bool

	Proto     int
	Detect    int
	AutoLevel int

	Hosts *filter.HostSet
	IPSet *filter.IPSet

	PF     [2]uint16
	Rounds [2]int

	RST bool

	OutType int
	OutAddr *net.TCPAddr

	CacheTTL  int
	CacheFile string

	ID        int
	Bit       uint64
	FailCount int
	Pri       int
	Calls     int
	Str       string

	Prev *DesyncParams
}

func (dp *DesyncParams) HasDetect(t int) bool { return dp.Detect&t != 0 }

func (dp *DesyncParams) HasProto(p int) bool { return dp.Proto&p != 0 }

func (dp *DesyncParams) RoundAllowed(round int) bool {
	if dp.Rounds[1] == 0 {
		return round <= 1
	}
	return round >= dp.Rounds[0] && round <= dp.Rounds[1]
}

func (dp *DesyncParams) HasL34Filters() bool {
	return dp.Proto != 0 || dp.PF[0] != 0 || dp.IPSet != nil
}

func (dp *DesyncParams) HasHostFilters() bool {
	return dp.Hosts != nil
}

type Params struct {
	DP         []*DesyncParams
	DPFullMask uint64
	AwaitInt   int
	WaitSend   bool

	DefTTL    int
	CustomTTL bool

	TFO           bool
	Timeout       uint32
	TLSTimeout    uint32
	TLSToCountLim int
	TLSToBytesLim int
	TCPToBytesLim int

	CachePre int

	Mode int

	IPv6    bool
	Resolve bool
	UDP     bool

	DelayConn     bool
	AutoReconnect bool

	MaxOpen int
	Debug   int
	BFSize  int

	BAddr *net.TCPAddr
	LAddr *net.TCPAddr

	ProtectPath string
	Daemonize   bool
	PidFile     string

	Version string
}

func NewParams() *Params {
	return &Params{
		AwaitInt:   10,
		IPv6:       true,
		Resolve:    true,
		UDP:        true,
		MaxOpen:    512,
		BFSize:     16384,
		DefTTL:     64,
		BAddr:      &net.TCPAddr{IP: net.IPv6unspecified},
		LAddr:      &net.TCPAddr{IP: net.IPv4zero, Port: 1080},
		Version:    "17.3-go",
		TLSTimeout: 0,
	}
}

func (p *Params) AddGroup(prev *DesyncParams) *DesyncParams {
	dp := &DesyncParams{
		ID:  len(p.DP),
		Bit: uint64(1) << len(p.DP),
	}
	p.DP = append(p.DP, dp)
	p.DPFullMask |= dp.Bit
	return dp
}

func (p *Params) FirstGroup() *DesyncParams {
	if len(p.DP) == 0 {
		return p.AddGroup(nil)
	}
	return p.DP[0]
}

func (p *Params) GroupByID(id int) *DesyncParams {
	if id < 0 || id >= len(p.DP) {
		return nil
	}
	return p.DP[id]
}

func (p *Params) DefaultRounds() [2]int { return [2]int{0, 0} }

type Timeouts struct {
	Dial       time.Duration
	FirstReply time.Duration
}

func (p *Params) FirstReplyTimeout() time.Duration {
	if p.TLSTimeout == 0 {
		return 0
	}
	return time.Duration(p.TLSTimeout) * time.Millisecond
}
