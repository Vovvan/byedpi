//go:build !linux

package proxy

import "syscall"

func protectFd(fd uintptr, path string) error { return syscall.ENOSYS }
