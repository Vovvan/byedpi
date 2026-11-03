//go:build linux

package config

import "syscall"

func sysDefaultTTL() int {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		return 0
	}
	defer syscall.Close(fd)
	v, err := syscall.GetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TTL)
	if err != nil {
		return 0
	}
	return v
}
