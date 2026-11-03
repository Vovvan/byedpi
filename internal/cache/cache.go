package cache

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"byedpi/internal/config"
)

type Entry struct {
	IP     net.IP
	Port   int
	Bits   int
	Time   time.Time
	Host   string
	Mask   uint64
	Detect int
	DP     *config.DesyncParams
}

type Cache struct {
	mu      sync.Mutex
	entries map[string]*Entry
}

func New() *Cache {
	return &Cache{entries: make(map[string]*Entry)}
}

func keyFor(ip net.IP, port int) string {
	if v4 := ip.To4(); v4 != nil {
		return "4:" + string(v4) + ":" + strconv.Itoa(port)
	}
	return "6:" + string(ip.To16()) + ":" + strconv.Itoa(port)
}

func (c *Cache) Get(ip net.IP, port int) *Entry {
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.entries[keyFor(ip, port)]
	if e == nil {
		return nil
	}
	if e.DP != nil && e.DP.CacheTTL > 0 && time.Since(e.Time) > time.Duration(e.DP.CacheTTL)*time.Second {
		delete(c.entries, keyFor(ip, port))
		return nil
	}
	cp := *e
	return &cp
}

func (c *Cache) Put(ip net.IP, port int, dp *config.DesyncParams, mask uint64, detect int, host string) *Entry {
	c.mu.Lock()
	defer c.mu.Unlock()
	k := keyFor(ip, port)
	e := c.entries[k]
	if e == nil {
		bits := 128
		if ip.To4() != nil {
			bits = 32
		}
		e = &Entry{IP: append(net.IP(nil), ip...), Port: port, Bits: bits}
		c.entries[k] = e
	}
	e.Time = time.Now()
	e.Mask |= mask
	e.Detect = detect
	e.DP = dp
	if host != "" {
		e.Host = host
	}
	return e
}

func (c *Cache) Delete(ip net.IP, port int) {
	c.mu.Lock()
	delete(c.entries, keyFor(ip, port))
	c.mu.Unlock()
}

func (c *Cache) Set(e *Entry, ip net.IP, port int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cp := *e
	cp.IP = append(net.IP(nil), ip...)
	cp.Port = port
	c.entries[keyFor(ip, port)] = &cp
}

func (c *Cache) LoadFile(path string, dp *config.DesyncParams) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return c.Load(f, dp)
}

func (c *Cache) Load(r io.Reader, dp *config.DesyncParams) error {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 || fields[0] != "0" {
			continue
		}
		ip := net.ParseIP(fields[1])
		if ip == nil {
			continue
		}
		bits, _ := strconv.Atoi(fields[2])
		port, _ := strconv.Atoi(fields[3])
		ts, _ := strconv.ParseInt(fields[4], 10, 64)
		host := fields[5]
		if host == "-" {
			host = ""
		}
		c.mu.Lock()
		k := keyFor(ip, port)
		c.entries[k] = &Entry{
			IP: ip, Port: port, Bits: bits, Time: time.Unix(ts, 0),
			Host: host, DP: dp,
		}
		c.mu.Unlock()
	}
	return sc.Err()
}

func (c *Cache) Dump(w io.Writer, dp *config.DesyncParams) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	bw := bufio.NewWriter(w)
	for _, e := range c.entries {
		if e.DP != dp {
			continue
		}
		host := e.Host
		if host == "" {
			host = "-"
		}
		fmt.Fprintf(bw, "0 %s %d %d %d %s\n", e.IP.String(), e.Bits, e.Port, e.Time.Unix(), host)
	}
	return bw.Flush()
}
