//go:build !linux && !windows

package desync

import (
	"net"
	"syscall"
)

const (
	TCPFastOpenConnect = 30
	TCPUserTimeout     = 18
	SOOriginalDst      = 80
)

func SetTTL(c net.Conn, ttl int) error                { return syscall.ENOSYS }
func SetUserTimeout(c net.Conn, ms uint32) error      { return syscall.ENOSYS }
func SetMD5Sig(c net.Conn, keyLen int) error          { return syscall.ENOSYS }
func SetSynCnt(c net.Conn, n int) error               { return syscall.ENOSYS }
func SetFastOpenConnect(c net.Conn) error             { return syscall.ENOSYS }
func DropSack(c net.Conn) error                       { return syscall.ENOSYS }
func DetachSack(c net.Conn) error                     { return syscall.ENOSYS }
func GetOriginalDst(c net.Conn) (*net.TCPAddr, error) { return nil, syscall.ENOSYS }

func ConfigureDialSocket(fd uintptr, ttl int, tfo bool) {}
