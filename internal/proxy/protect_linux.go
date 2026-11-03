//go:build linux

package proxy

import (
	"syscall"
	"time"
	"unsafe"
)

func protectFd(fd uintptr, path string) error {
	s, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(s)
	tv := syscall.NsecToTimeval(time.Second.Nanoseconds())
	syscall.SetsockoptTimeval(s, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
	syscall.SetsockoptTimeval(s, syscall.SOL_SOCKET, syscall.SO_SNDTIMEO, &tv)

	sa := &syscall.SockaddrUnix{Name: path}
	if err := syscall.Connect(s, sa); err != nil {
		return err
	}
	buf := make([]byte, 1)
	oob := syscall.UnixRights(int(fd))
	msg := syscall.Msghdr{
		Iov:        &syscall.Iovec{Base: &buf[0], Len: 1},
		Iovlen:     1,
		Control:    &oob[0],
		Controllen: uint64(len(oob)),
	}
	if _, _, e := syscall.Syscall(syscall.SYS_SENDMSG, uintptr(s), uintptr(unsafe.Pointer(&msg)), 0); e != 0 {
		return e
	}
	if _, err := syscall.Read(s, buf); err != nil {
		return err
	}
	return nil
}
