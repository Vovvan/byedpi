//go:build !windows

package desync

import (
	"net"
	"syscall"
)

func sendOOB(c net.Conn, p []byte) (int, error) {
	if len(p) == 0 {
		return 0, syscall.EINVAL
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
	sent := 0
	var sendErr error
	err = rc.Write(func(fd uintptr) bool {
		for sent < len(p) {
			n, e := syscall.SendmsgN(int(fd), p[sent:], nil, nil, syscall.MSG_OOB)
			if e == syscall.EAGAIN || e == syscall.EWOULDBLOCK {
				return false
			}
			if e != nil {
				sendErr = e
				return true
			}
			sent += n
		}
		return true
	})
	if err != nil {
		return sent, err
	}
	return sent, sendErr
}
