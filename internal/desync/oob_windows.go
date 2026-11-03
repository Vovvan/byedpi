//go:build windows

package desync

import (
	"net"
	"syscall"
)

const msgOOB = 0x1

func sendOOB(c net.Conn, p []byte) (int, error) {
	if len(p) == 0 {
		return 0, syscall.EINVAL
	}
	if len(p) > 1 {
		if err := sendAll(c, p[:len(p)-1]); err != nil {
			return 0, err
		}
	}
	type syscallConner interface {
		SyscallConn() (syscall.RawConn, error)
	}
	sc, ok := c.(syscallConner)
	if !ok {
		return 0, syscall.EINVAL
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return 0, err
	}
	last := p[len(p)-1]
	sent := 0
	var sendErr error
	err = rc.Write(func(fd uintptr) bool {
		buf := syscall.WSABuf{Len: 1, Buf: &last}
		var n uint32
		e := syscall.WSASend(syscall.Handle(fd), &buf, 1, &n, msgOOB, nil, nil)
		if e == syscall.EAGAIN || e == syscall.EWOULDBLOCK {
			return false
		}
		if e != nil {
			sendErr = e
			return true
		}
		if n == 0 {
			sendErr = syscall.EIO
			return true
		}
		sent += int(n)
		return true
	})
	if err != nil {
		return 0, err
	}
	if sendErr != nil {
		return 0, sendErr
	}
	return len(p) - 1 + sent, nil
}
