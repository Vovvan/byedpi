//go:build !linux

package config

func sysDefaultTTL() int { return 64 }
