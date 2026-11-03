//go:build windows

package main

import (
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"byedpi/internal/config"
	"byedpi/internal/proxy"
)

const detachedProcess = 0x00000008

func daemonize() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	devnull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer devnull.Close()
	cmd := exec.Command(exe, os.Args[1:]...)
	cmd.Env = append(os.Environ(), "BYEDPI_DAEMON=1")
	cmd.Stdin = devnull
	cmd.Stdout = devnull
	cmd.Stderr = devnull
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: detachedProcess | syscall.CREATE_NEW_PROCESS_GROUP,
	}
	return cmd.Start()
}

func openPidFile(path string) (*os.File, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := syscall.CreateFile(p,
		syscall.GENERIC_READ|syscall.GENERIC_WRITE,
		0,
		nil,
		syscall.OPEN_ALWAYS,
		syscall.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(h), path), nil
}

func raiseFileLimit(maxConn int) {}

func setupSignals(cfg *config.Params, srv *proxy.Server) {
	sig := make(chan os.Signal, 2)
	signal.Notify(sig, os.Interrupt)
	go func() {
		for range sig {
			srv.Close()
			return
		}
	}()
}
