package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

func ParseCForm(s string) []byte {
	var out []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' {
			out = append(out, c)
			continue
		}
		i++
		if i >= len(s) {
			break
		}
		switch s[i] {
		case 'r':
			out = append(out, '\r')
		case 'n':
			out = append(out, '\n')
		case 't':
			out = append(out, '\t')
		case '\\':
			out = append(out, '\\')
		case 'f':
			out = append(out, '\f')
		case 'b':
			out = append(out, '\b')
		case 'v':
			out = append(out, '\v')
		case 'a':
			out = append(out, '\a')
		case 'x':
			if i+2 < len(s) {
				if v, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
					out = append(out, byte(v))
					i += 2
				}
			}
		default:
			if s[i] >= '0' && s[i] <= '7' {
				j := i
				for j < len(s) && j < i+3 && s[j] >= '0' && s[j] <= '7' {
					j++
				}
				if v, err := strconv.ParseUint(s[i:j], 8, 8); err == nil {
					out = append(out, byte(v))
					i = j - 1
				}
			}
		}
	}
	return out
}

func DataFromStr(s string) []byte {
	if s == "" {
		return nil
	}
	out := ParseCForm(s)
	if len(out) == 0 {
		return nil
	}
	return out
}

func ReadData(s string) ([]byte, error) {
	if strings.HasPrefix(s, ":") {
		d := DataFromStr(s[1:])
		if len(d) == 0 {
			return nil, fmt.Errorf("empty data")
		}
		return d, nil
	}
	return os.ReadFile(s)
}

func ParseHosts(h HostSetLike, data []byte, log func(int, string, ...any)) error {
	fields := strings.FieldsFunc(string(data), func(r rune) bool {
		return r == ' ' || r == '\n' || r == '\r'
	})
	n := 0
	for _, f := range fields {
		if h.Add(f) {
			n++
		} else if log != nil {
			log(1, "invalid host: %q\n", f)
		}
	}
	if log != nil {
		log(2, "hosts count: %d\n", h.Len())
	}
	return nil
}

type HostSetLike interface {
	Add(string) bool
	Len() int
}

type IPSetLike interface {
	Add(string) bool
	Len() int
}

func ParseIPSet(s IPSetLike, data []byte, log func(int, string, ...any)) error {
	fields := strings.FieldsFunc(string(data), func(r rune) bool {
		return r == ' ' || r == '\n' || r == '\r'
	})
	for i, f := range fields {
		if !s.Add(f) {
			if log != nil {
				log(1, "invalid ip: num: %d\n", i+1)
			}
		}
	}
	if log != nil {
		log(2, "ip count: %d\n", s.Len())
	}
	return nil
}

func parseLong(s string) (int64, string, error) {
	i := 0
	if i < len(s) && (s[i] == '+' || s[i] == '-') {
		i++
	}
	if i+2 <= len(s) && s[i] == '0' && (s[i+1] == 'x' || s[i+1] == 'X') {
		i += 2
		for i < len(s) && isHex(s[i]) {
			i++
		}
	} else {
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
		}
	}
	if i == 0 || (i == 1 && (s[0] == '+' || s[0] == '-')) {
		return 0, s, fmt.Errorf("bad number")
	}
	v, err := strconv.ParseInt(s[:i], 0, 64)
	if err != nil {
		return 0, s[i:], err
	}
	return v, s[i:], nil
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func ParseOffset(p *Part, s string) error {
	val, rest, err := parseLong(s)
	if err != nil {
		return err
	}
	for strings.HasPrefix(rest, ":") {
		rs, r2, err := parseLong(rest[1:])
		if err != nil || rs < 0 || rs > int64(^uint(0)>>1) {
			return fmt.Errorf("bad repeat")
		}
		rest = r2
		if p.Repeats == 0 {
			if rs == 0 {
				return fmt.Errorf("bad repeat")
			}
			p.Repeats = int(rs)
		} else {
			p.Skip = int(rs)
			break
		}
	}
	if strings.HasPrefix(rest, "+") {
		if len(rest) < 2 {
			return fmt.Errorf("bad flag")
		}
		switch rest[1] {
		case 's':
			p.Flags = OffsetSNI
		case 'h':
			p.Flags = OffsetHost
		case 'n':
			p.Flags = 0
		default:
			return fmt.Errorf("bad flag")
		}
		if len(rest) >= 3 {
			switch rest[2] {
			case 'e':
				p.Flags |= OffsetEnd
			case 'm':
				p.Flags |= OffsetMid
			case 'r':
				p.Flags |= OffsetRand
			case 's':
				p.Flags |= OffsetStart
			}
		}
	} else if rest != "" {
		return fmt.Errorf("trailing data")
	}
	p.Pos = val
	return nil
}

func ParsePortRange(s string) (uint16, uint16, error) {
	parts := strings.SplitN(s, "-", 2)
	a, err := strconv.Atoi(parts[0])
	if err != nil || a <= 0 || a > 0xffff {
		return 0, 0, fmt.Errorf("bad port")
	}
	b := a
	if len(parts) == 2 {
		b, err = strconv.Atoi(parts[1])
		if err != nil || b <= 0 || b > 0xffff {
			return 0, 0, fmt.Errorf("bad port")
		}
	}
	return uint16(a), uint16(b), nil
}

func ParseRoundRange(s string) (int, int, error) {
	parts := strings.SplitN(s, "-", 2)
	a, err := strconv.Atoi(parts[0])
	if err != nil || a <= 0 {
		return 0, 0, fmt.Errorf("bad round")
	}
	b := a
	if len(parts) == 2 {
		b, err = strconv.Atoi(parts[1])
		if err != nil || b <= 0 {
			return 0, 0, fmt.Errorf("bad round")
		}
	}
	return a, b, nil
}
