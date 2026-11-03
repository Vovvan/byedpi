//go:build windows

package desync

import (
	"net"
	"syscall"
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
	return rc.Control(func(fd uintptr) { fn(int(fd)) })
}

func SetTTL(c net.Conn, ttl int) error {
	return rawControl(c, func(fd int) {
		syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
		syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS, ttl)
	})
}

func SetUserTimeout(c net.Conn, ms uint32) error      { return syscall.ENOSYS }
func SetMD5Sig(c net.Conn, keyLen int) error          { return syscall.ENOSYS }
func SetSynCnt(c net.Conn, n int) error               { return syscall.ENOSYS }
func SetFastOpenConnect(c net.Conn) error             { return syscall.ENOSYS }
func DropSack(c net.Conn) error                       { return syscall.ENOSYS }
func DetachSack(c net.Conn) error                     { return syscall.ENOSYS }
func GetOriginalDst(c net.Conn) (*net.TCPAddr, error) { return nil, syscall.ENOSYS }

func ConfigureDialSocket(fd uintptr, ttl int, tfo bool) {
	f := int(fd)
	syscall.SetsockoptInt(syscall.Handle(f), syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1)
	if ttl > 0 {
		syscall.SetsockoptInt(syscall.Handle(f), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
		syscall.SetsockoptInt(syscall.Handle(f), syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS, ttl)
	}
}
