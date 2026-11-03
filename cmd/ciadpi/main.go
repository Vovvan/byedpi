package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"byedpi/internal/config"
	"byedpi/internal/proxy"
)

func main() {
	os.Exit(run())
}

func run() int {
	debug := 0
	logf := func(level int, format string, args ...any) {
		if level > debug+1 {
			return
		}
		fmt.Fprintf(os.Stderr, format, args...)
	}

	var args []string
	ssLocal := os.Getenv("SS_LOCAL_PORT")
	ssOpts := os.Getenv("SS_PLUGIN_OPTIONS")
	if ssOpts != "" {
		args = strings.Fields(ssOpts)
	} else {
		args = os.Args[1:]
	}

	cfg, err := config.ParseArgs(args, logf)
	if err != nil {
		if errors.Is(err, config.ErrHelp) {
			fmt.Print(config.HelpText)
			return 0
		}
		if errors.Is(err, config.ErrVersion) {
			fmt.Println("17.3-go")
			return 0
		}
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	debug = cfg.Debug
	if ssLocal != "" {
		if p, err := strconv.Atoi(ssLocal); err == nil {
			cfg.LAddr.Port = p
		}
		cfg.Mode |= config.ModeShadowsocks
		if _, err := os.Stat("protect_path"); err == nil {
			cfg.ProtectPath = "protect_path"
		}
	}

	if cfg.Daemonize && os.Getenv("BYEDPI_DAEMON") != "1" {
		if err := daemonize(); err != nil {
			fmt.Fprintf(os.Stderr, "daemon: %v\n", err)
			return 1
		}
		return 0
	}

	pidFile, err := writePidFile(cfg.PidFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pidfile: %v\n", err)
		return 1
	}
	if pidFile != nil {
		defer func() {
			pidFile.Close()
			os.Remove(cfg.PidFile)
		}()
	}

	raiseFileLimit(cfg.MaxOpen)

	srv := proxy.New(cfg, logf)
	for _, dp := range cfg.DP {
		if dp.CacheFile != "" && dp.CacheFile != "-" {
			if err := srv.Cache.LoadFile(dp.CacheFile, dp); err != nil {
				fmt.Fprintf(os.Stderr, "load cache: %v\n", err)
			} else {
				fmt.Fprintf(os.Stderr, "cache loaded: %s\n", dp.CacheFile)
			}
		}
	}

	setupSignals(cfg, srv)

	err = srv.Run()
	dumpCaches(cfg, srv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "run: %v\n", err)
		return 1
	}
	return 0
}

func dumpCaches(cfg *config.Params, srv *proxy.Server) {
	for _, dp := range cfg.DP {
		if dp.CacheFile == "" {
			continue
		}
		if dp.CacheFile == "-" {
			srv.Cache.Dump(os.Stdout, dp)
			continue
		}
		f, err := os.Create(dp.CacheFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dump cache: %v\n", err)
			continue
		}
		srv.Cache.Dump(f, dp)
		f.Close()
	}
}

func writePidFile(path string) (*os.File, error) {
	if path == "" {
		return nil, nil
	}
	f, err := openPidFile(path)
	if err != nil {
		return nil, err
	}
	if err := f.Truncate(0); err != nil {
		f.Close()
		return nil, err
	}
	if _, err := f.WriteString(strconv.Itoa(os.Getpid())); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}
