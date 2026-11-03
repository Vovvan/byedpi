package packets

import (
	"bytes"
	"math/rand"
	"strings"

	"byedpi/internal/config"
)

func be16(b []byte) uint16 { return uint16(b[0])<<8 | uint16(b[1]) }

func put16(b []byte, v uint16) {
	b[0] = byte(v >> 8)
	b[1] = byte(v)
}

func IsTLSClientHello(b []byte) bool {
	return len(b) > 5 && be16(b) == 0x1603 && b[5] == 0x01
}

func IsTLSServerHello(b []byte) bool {
	return len(b) > 5 && be16(b) == 0x1603 && b[5] == 0x02
}

func findTLSExtOffset(typ uint16, data []byte, size, skip int) int {
	if size <= skip+2 {
		return 0
	}
	extLen := int(be16(data[skip:]))
	skip += 2
	if extLen < size-skip {
		size = skip + extLen
	}
	for skip+4 < size {
		et := be16(data[skip:])
		if et == typ {
			return skip
		}
		l := int(be16(data[skip+2:]))
		skip += l + 4
	}
	return 0
}

func findExtBlock(data []byte, size int) int {
	if size < 44 {
		return 0
	}
	sidLen := int(data[43])
	if size < 44+sidLen+2 {
		return 0
	}
	cipLen := int(be16(data[44+sidLen:]))
	skip := 44 + sidLen + 2 + cipLen + 2
	if skip > size {
		return 0
	}
	return skip
}

// ParseTLS returns the offset and length of the SNI host name.
func ParseTLS(data []byte) (hostOff, hostLen int, ok bool) {
	n := len(data)
	if !IsTLSClientHello(data) {
		return 0, 0, false
	}
	skip := findExtBlock(data, n)
	if skip == 0 {
		return 0, 0, false
	}
	sni := findTLSExtOffset(0, data, n, skip)
	if sni == 0 || sni+12 >= n {
		return 0, 0, false
	}
	l := int(be16(data[sni+7:]))
	if sni+9+l > n {
		return 0, 0, false
	}
	return sni + 9, l, true
}

var httpMethods = []string{
	"HEAD", "GET", "POST", "PUT", "DELETE",
	"OPTIONS", "CONNECT", "TRACE", "PATCH",
}

func IsHTTP(b []byte) bool {
	if len(b) < 16 || b[0] > 'T' || b[0] < 'C' {
		return false
	}
	for _, m := range httpMethods {
		if bytes.HasPrefix(b, []byte(m)) {
			return true
		}
	}
	return false
}

// ParseHTTP returns the offset/length of the Host header value and its port.
func ParseHTTP(b []byte) (hostOff, hostLen, port int, ok bool) {
	if !IsHTTP(b) {
		return 0, 0, 0, false
	}
	low := bytes.ToLower(b)
	idx := bytes.Index(low, []byte("\nhost:"))
	if idx < 0 {
		return 0, 0, 0, false
	}
	start := idx + 6
	for start < len(b) && b[start] == ' ' {
		start++
	}
	nl := bytes.IndexByte(b[start:], '\n')
	if nl < 0 {
		return 0, 0, 0, false
	}
	end := start + nl
	for end > start && isSpace(b[end-1]) {
		end--
	}
	hEnd := end
	for hEnd > start && b[hEnd-1] >= '0' && b[hEnd-1] <= '9' {
		hEnd--
	}
	port = 80
	if hEnd > start && b[hEnd-1] == ':' {
		p := 0
		for i := hEnd; i < end; i++ {
			if b[i] < '0' || b[i] > '9' {
				return 0, 0, 0, false
			}
			p = p*10 + int(b[i]-'0')
		}
		if p <= 0 || p > 0xffff {
			return 0, 0, 0, false
		}
		port = p
		hEnd--
	} else {
		hEnd = end
	}
	hostStart := start
	hostEnd := hEnd
	if hostStart < len(b) && b[hostStart] == '[' {
		if hostEnd <= hostStart || b[hostEnd-1] != ']' {
			return 0, 0, 0, false
		}
		hostStart++
		hostEnd--
	}
	return hostStart, hostEnd - hostStart, port, true
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\v' || c == '\f'
}

func httpCode(b []byte) int {
	if len(b) < 13 || !bytes.HasPrefix(b, []byte("HTTP/1.")) {
		return 0
	}
	if bytes.IndexByte(b[12:], '\n') < 0 {
		return 0
	}
	i := 9
	for i < len(b) && b[i] >= '0' && b[i] <= '9' {
		i++
	}
	if i == 9 || i >= len(b) || !isSpace(b[i]) {
		return 0
	}
	n := 0
	for _, c := range b[9:i] {
		n = n*10 + int(c-'0')
	}
	if n < 100 || n > 511 {
		return 0
	}
	return n
}

func IsHTTPRedirect(req, resp []byte) bool {
	_, hl, _, ok := ParseHTTP(req)
	if !ok || hl <= 0 || len(resp) < 29 {
		return false
	}
	code := httpCode(resp)
	if code < 300 || code > 308 {
		return false
	}
	low := bytes.ToLower(resp)
	idx := bytes.Index(low, []byte("\nlocation:"))
	if idx < 0 {
		return false
	}
	loc := idx + 11
	if loc+8 >= len(resp) {
		return false
	}
	nl := bytes.IndexByte(resp[loc:], '\n')
	if nl < 0 {
		return false
	}
	lEnd := loc + nl
	for lEnd > loc && isSpace(resp[lEnd-1]) {
		lEnd--
	}
	if lEnd-loc > 7 {
		if bytes.HasPrefix(resp[loc:], []byte("http://")) {
			loc += 7
		} else if bytes.HasPrefix(resp[loc:], []byte("https://")) {
			loc += 8
		}
	}
	if loc > lEnd {
		return false
	}
	le := lEnd
	if p := bytes.IndexByte(resp[loc:lEnd], '/'); p >= 0 {
		le = loc + p
	}
	hostOff, hostLen, _, ok := ParseHTTP(req)
	if !ok || hostLen <= 0 {
		return false
	}
	host := req[hostOff : hostOff+hostLen]
	// Compare the registrable part (last three labels) as the C implementation does.
	he := host
	h := he
	for i := 0; i < 2 && len(h) > 0; i++ {
		q := bytes.LastIndexByte(h[:len(h)-1], '.')
		if q < 0 {
			h = h[:0]
			break
		}
		h = h[:q+1]
	}
	suffix := he[len(h):]
	if len(suffix) == 0 {
		suffix = he
	}
	lhost := resp[loc:le]
	if len(suffix) > len(lhost) {
		return true
	}
	return !bytes.Equal(lhost[len(lhost)-len(suffix):], suffix)
}

func NeqTLSSID(req, resp []byte) bool {
	if len(req) < 75 || len(resp) < 75 {
		return false
	}
	if !IsTLSClientHello(req) || be16(resp) != 0x1603 {
		return false
	}
	sidLen := int(req[43])
	skip := 44 + sidLen + 3
	if findTLSExtOffset(0x2b, resp, len(resp), skip) == 0 {
		return false
	}
	if req[43] != resp[43] {
		return true
	}
	if len(req) < 44+sidLen || len(resp) < 44+sidLen {
		return false
	}
	return !bytes.Equal(req[44:44+sidLen], resp[44:44+sidLen])
}

func mergeTLSRecords(buf []byte, n int) int {
	if n < 5 {
		return 0
	}
	full := 0
	rSz := int(be16(buf[3:]))
	i := 0
	for {
		full += rSz
		if 5+full > n-5 || buf[5+full] != buf[0] {
			break
		}
		rSz = int(be16(buf[5+full+3:]))
		if full+10+rSz > n {
			break
		}
		copy(buf[5+full:], buf[10+full:n])
		i++
	}
	put16(buf[3:], uint16(full))
	put16(buf[7:], uint16(full-4))
	return i * 5
}

func copyName(out []byte, name string) {
	for i := 0; i < len(out) && i < len(name); i++ {
		switch name[i] {
		case '*':
			r := rand.Intn(10 + 'z' - 'a' + 1)
			if r < 10 {
				out[i] = byte('0' + r)
			} else {
				out[i] = byte('a' - 10 + r)
			}
		case '?':
			out[i] = byte('a' + rand.Intn('z'-'a'+1))
		case '#':
			out[i] = byte('0' + rand.Intn(10))
		default:
			out[i] = name[i]
		}
	}
}

func removeKSGroup(buf []byte, n, skip int, group uint16) int {
	ks := findTLSExtOffset(0x0033, buf, n, skip)
	if ks == 0 || ks+6 >= n {
		return 0
	}
	ksSz := int(be16(buf[ks+2:]))
	if ks+4+ksSz > n {
		return 0
	}
	g := ks + 4 + 2
	for g+4 < ks+4+ksSz {
		gSz := int(be16(buf[g+2:]))
		if ks+4+gSz > n {
			return 0
		}
		if be16(buf[g:]) == group {
			gEnd := g + 4 + gSz
			copy(buf[g:], buf[gEnd:n])
			put16(buf[ks+2:], uint16(ksSz-(4+gSz)))
			put16(buf[ks+4:], uint16(ksSz-(4+gSz)-2))
			return 4 + gSz
		}
		g += 4 + gSz
	}
	return 0
}

func removeTLSExt(buf []byte, n, skip int, typ uint16) int {
	off := findTLSExtOffset(typ, buf, n, skip)
	if off == 0 {
		return 0
	}
	sz := int(be16(buf[off+2:]))
	end := off + 4 + sz
	if end > n {
		return 0
	}
	copy(buf[off:], buf[end:n])
	return sz + 4
}

func resizeECHExt(buf []byte, n, skip, inc int) int {
	off := findTLSExtOffset(0xfe0d, buf, n, skip)
	if off == 0 {
		return 0
	}
	echSz := int(be16(buf[off+2:]))
	echEnd := off + 4 + echSz
	if echSz < 12 || echEnd > n {
		return 0
	}
	encSz := int(be16(buf[off+4+6:]))
	payOff := off + 4 + 8 + encSz
	paySz := echSz - (8 + encSz + 2)
	if payOff+2 > n {
		return 0
	}
	if paySz < -inc {
		inc = -paySz
	}
	put16(buf[off+2:], uint16(echSz+inc))
	put16(buf[payOff:], uint16(paySz+inc))
	copy(buf[echEnd+inc:], buf[echEnd:n])
	return inc
}

func resizeSNI(buf []byte, n, sniOff, sniSz, newSz int) {
	put16(buf[sniOff+2:], uint16(newSz+5))
	put16(buf[sniOff+4:], uint16(newSz+3))
	put16(buf[sniOff+7:], uint16(newSz))
	sniEnd := sniOff + 4 + sniSz
	dst := sniEnd + newSz - (sniSz - 5)
	copy(buf[dst:], buf[sniEnd:n])
}

// ChangeTLSSNI rewrites the SNI in a ClientHello. nn is the effective fake size.
func ChangeTLSSNI(host string, buf []byte, n, nn int) bool {
	avail := mergeTLSRecords(buf, n)
	avail += nn - n

	rSz := int(be16(buf[3:]))
	rSz += avail

	skip := findExtBlock(buf, n)
	if skip == 0 {
		return false
	}
	sniOff := findTLSExtOffset(0, buf, n, skip)
	if sniOff == 0 {
		return false
	}
	newSz := len(host)
	sniSz := int(be16(buf[sniOff+2:]))
	if sniOff+4+sniSz > n {
		return false
	}
	diff := newSz - (sniSz - 5)
	avail -= diff

	if diff < 0 && avail > 0 {
		resizeSNI(buf, n, sniOff, sniSz, newSz)
		diff = 0
	}
	if avail != 0 {
		avail -= resizeECHExt(buf, n, skip, avail)
	}
	if avail < -50 {
		avail += removeKSGroup(buf, n, skip, 0x11ec)
	}
	exts := []uint16{
		0x0015, 0x0031, 0x0010, 0x001c, 0x0023,
		0x0005, 0x0022, 0x0012, 0x001b,
	}
	for _, e := range exts {
		if avail == 0 || avail >= 4 {
			break
		}
		avail += removeTLSExt(buf, n, skip, e)
	}
	if avail != 0 && avail < 4 {
		return false
	}
	sniOff = findTLSExtOffset(0, buf, n, skip)
	if sniOff == 0 {
		return false
	}
	if diff != 0 {
		resizeSNI(buf, n, sniOff, sniSz, newSz)
	}
	if newSz > len(buf) {
		return false
	}
	copyName(buf[sniOff+9:sniOff+9+newSz], host)

	if avail > 0 {
		avail -= resizeECHExt(buf, n, skip, avail)
	}
	if avail >= 4 {
		base := 5 + rSz - avail
		if base >= 0 && base+4 <= len(buf) {
			put16(buf[base:], 0x0015)
			put16(buf[base+2:], uint16(avail-4))
			if base+avail <= len(buf) {
				for i := base + 4; i < base+avail; i++ {
					buf[i] = 0
				}
			}
		}
	}
	put16(buf[3:], uint16(rSz))
	put16(buf[7:], uint16(rSz-4))
	if skip+2 <= len(buf) {
		put16(buf[skip:], uint16(5+rSz-skip-2))
	}
	return true
}

func ModHTTP(buf []byte, m int) bool {
	hostOff, hlen, _, ok := ParseHTTP(buf)
	if !ok || hlen == 0 {
		return false
	}
	// find the method name preceding the host
	par := hostOff - 1
	for par >= 0 && buf[par] != ':' {
		par--
	}
	par -= 4
	if par < 0 {
		return false
	}
	if m&config.MHHMix != 0 {
		buf[par] = lower(buf[par])
		buf[par+1] = upper(buf[par+1])
		buf[par+3] = upper(buf[par+3])
	}
	if m&config.MHDMix != 0 {
		for i := 0; i < hlen; i += 2 {
			buf[hostOff+i] = upper(buf[hostOff+i])
		}
	}
	if m&config.MHSpace != 0 {
		end := hostOff + hlen
		for end < len(buf) && !isSpace(buf[end]) {
			end++
		}
		sc := hostOff - (par + 5)
		copy(buf[par+5:], buf[hostOff:end])
		for i := 0; i < sc && par+5+end-hostOff+i < len(buf); i++ {
			buf[par+5+end-hostOff+i] = '\t'
		}
	}
	return true
}

func lower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 32
	}
	return c
}

func upper(c byte) byte {
	if c >= 'a' && c <= 'z' {
		return c - 32
	}
	return c
}

func PartTLS(buf []byte, bsize, n int, pos int64) int {
	if n < 3 || bsize-n < 5 || pos < 0 || pos+5 > int64(n) {
		return 0
	}
	p := int(pos)
	rSz := int(be16(buf[3:]))
	if int64(rSz) < pos {
		return n
	}
	copy(buf[5+p+5:], buf[5+p:n])
	copy(buf[5+p:], buf[:3])
	put16(buf[3:], uint16(p))
	put16(buf[5+p+3:], uint16(rSz-p))
	return 5
}

func RandomizeTLS(buf []byte, n int) {
	if n < 44 {
		return
	}
	sidLen := int(buf[43])
	if n < 44+sidLen+2 {
		return
	}
	for i := 0; i < 32 && 11+i < n; i++ {
		buf[11+i] = byte(rand.Intn(256))
	}
	for i := 0; i < sidLen && 44+i < n; i++ {
		buf[44+i] = byte(rand.Intn(256))
	}
	skip := findExtBlock(buf, n)
	if skip == 0 {
		return
	}
	ks := findTLSExtOffset(0x0033, buf, n, skip)
	if ks == 0 || ks+6 >= n {
		return
	}
	ksSz := int(be16(buf[ks+2:]))
	if ks+4+ksSz > n {
		return
	}
	g := ks + 4 + 2
	for g+4 < ks+4+ksSz {
		gSz := int(be16(buf[g+2:]))
		if ks+4+gSz > n {
			return
		}
		for i := 0; i < gSz && g+4+i < n; i++ {
			buf[g+4+i] = byte(rand.Intn(256))
		}
		g += 4 + gSz
	}
}

func HostString(buf []byte) string {
	if off, l, ok := ParseTLS(buf); ok {
		return strings.ToLower(string(buf[off : off+l]))
	}
	if off, l, _, ok := ParseHTTP(buf); ok {
		return strings.ToLower(string(buf[off : off+l]))
	}
	return ""
}
