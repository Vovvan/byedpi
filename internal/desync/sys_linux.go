//go:build linux

package desync

import (
	"net"
	"syscall"
	"unsafe"
)

const (
	TCPFastOpenConnect = 30
	TCPUserTimeout     = 18
	SOOriginalDst      = 80
)

func rawControl(c net.Conn, fn func(fd int)) error {
	type syscallConner interface {
		SyscallConn() (syscall.RawConn, error)
	}
	sc, ok := c.(syscallConner)
	if !ok {
		return syscall.EINVAL
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return err
	}
	var inner error
	if err := rc.Control(func(fd uintptr) { fn(int(fd)) }); err != nil {
		return err
	}
	return inner
}

func SetTTL(c net.Conn, ttl int) error {
	return rawControl(c, func(fd int) {
		syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
		syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS, ttl)
	})
}

func SetUserTimeout(c net.Conn, ms uint32) error {
	return rawControl(c, func(fd int) {
		syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, TCPUserTimeout, int(ms))
	})
}

type tcpMD5Sig struct {
	Addr      [128]byte
	Flags     uint8
	PrefixLen uint8
	KeyLen    uint16
	Pad       uint32
	Key       [80]byte
}

func SetMD5Sig(c net.Conn, keyLen int) error {
	var sig tcpMD5Sig
	ra := c.RemoteAddr()
	switch a := ra.(type) {
	case *net.TCPAddr:
		if v4 := a.IP.To4(); v4 != nil {
			sa := syscall.RawSockaddrInet4{Family: syscall.AF_INET}
			copy(sa.Addr[:], v4)
			sa.Port = uint16(a.Port)
			*(*syscall.RawSockaddrInet4)(unsafe.Pointer(&sig.Addr[0])) = sa
		} else {
			sa := syscall.RawSockaddrInet6{Family: syscall.AF_INET6}
			copy(sa.Addr[:], a.IP.To16())
			sa.Port = uint16(a.Port)
			if a.Zone != "" {
				if ifi, err := net.InterfaceByName(a.Zone); err == nil {
					sa.Scope_id = uint32(ifi.Index)
				}
			}
			*(*syscall.RawSockaddrInet6)(unsafe.Pointer(&sig.Addr[0])) = sa
		}
	default:
		return syscall.EINVAL
	}
	sig.KeyLen = uint16(keyLen)
	return rawControl(c, func(fd int) {
		syscall.SetsockoptString(fd, syscall.IPPROTO_TCP, syscall.TCP_MD5SIG, string(unsafe.Slice((*byte)(unsafe.Pointer(&sig)), int(unsafe.Sizeof(sig)))))
	})
}

func SetSynCnt(c net.Conn, n int) error {
	return rawControl(c, func(fd int) {
		syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, syscall.TCP_SYNCNT, n)
	})
}

func SetFastOpenConnect(c net.Conn) error {
	return rawControl(c, func(fd int) {
		syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, TCPFastOpenConnect, 1)
	})
}

func DropSack(c net.Conn) error {
	code := []syscall.SockFilter{
		{Code: 0x30, K: 0x0000000c},
		{Code: 0x74, K: 0x00000004},
		{Code: 0x35, Jf: 3, K: 0x0000000b},
		{Code: 0x30, K: 0x00000022},
		{Code: 0x15, Jf: 1, K: 0x00000005},
		{Code: 0x6, K: 0x00000000},
		{Code: 0x6, K: 0x00040000},
	}
	fprog := syscall.SockFprog{Len: uint16(len(code)), Filter: &code[0]}
	var ret error
	err := rawControl(c, func(fd int) {
		_, _, e := syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(fd),
			uintptr(syscall.SOL_SOCKET), uintptr(syscall.SO_ATTACH_FILTER),
			uintptr(unsafe.Pointer(&fprog)), unsafe.Sizeof(fprog), 0)
		if e != 0 {
			ret = e
		}
	})
	if err != nil {
		return err
	}
	return ret
}

func DetachSack(c net.Conn) error {
	return rawControl(c, func(fd int) {
		syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_DETACH_FILTER, 0)
	})
}

func GetOriginalDst(c net.Conn) (*net.TCPAddr, error) {
	sc, ok := c.(interface {
		SyscallConn() (syscall.RawConn, error)
	})
	if !ok {
		return nil, syscall.EINVAL
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return nil, err
	}
	var out *net.TCPAddr
	var inner error
	rc.Control(func(fd uintptr) {
		var sa syscall.RawSockaddrInet4
		l := uint32(unsafe.Sizeof(sa))
		_, _, e := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, syscall.IPPROTO_IP, SOOriginalDst,
			uintptr(unsafe.Pointer(&sa)), uintptr(unsafe.Pointer(&l)), 0)
		if e == 0 {
			ip := net.IPv4(sa.Addr[0], sa.Addr[1], sa.Addr[2], sa.Addr[3])
			out = &net.TCPAddr{IP: ip, Port: int(sa.Port)}
			return
		}
		var sa6 syscall.RawSockaddrInet6
		l = uint32(unsafe.Sizeof(sa6))
		_, _, e = syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, syscall.IPPROTO_IPV6, SOOriginalDst,
			uintptr(unsafe.Pointer(&sa6)), uintptr(unsafe.Pointer(&l)), 0)
		if e == 0 {
			ip := make(net.IP, 16)
			copy(ip, sa6.Addr[:])
			out = &net.TCPAddr{IP: ip, Port: int(sa6.Port)}
			return
		}
		inner = e
	})
	if out == nil && inner != nil {
		return nil, inner
	}
	return out, nil
}

func ConfigureDialSocket(fd uintptr, ttl int, tfo bool) {
	f := int(fd)
	syscall.SetsockoptInt(f, syscall.IPPROTO_TCP, syscall.TCP_SYNCNT, 1)
	syscall.SetsockoptInt(f, syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1)
	if tfo {
		syscall.SetsockoptInt(f, syscall.IPPROTO_TCP, TCPFastOpenConnect, 1)
	}
	if ttl > 0 {
		syscall.SetsockoptInt(f, syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
		syscall.SetsockoptInt(f, syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS, ttl)
	}
}
