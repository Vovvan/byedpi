package proxy

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"

	"byedpi/internal/cache"
	"byedpi/internal/config"
)

type Logger func(level int, format string, args ...any)

type Server struct {
	Cfg   *config.Params
	Cache *cache.Cache
	Log   Logger

	mu        sync.Mutex
	listeners []*net.TCPListener
	conns     map[net.Conn]struct{}
	sem       chan struct{}
	closed    int32
	wg        sync.WaitGroup
}

func New(cfg *config.Params, l Logger) *Server {
	return &Server{
		Cfg:   cfg,
		Cache: cache.New(),
		Log:   l,
		conns: make(map[net.Conn]struct{}),
		sem:   make(chan struct{}, cfg.MaxOpen),
	}
}

func (s *Server) log(level int, format string, args ...any) {
	if s.Log != nil {
		s.Log(level, format, args...)
	}
}

func (s *Server) track(c net.Conn, add bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if add {
		s.conns[c] = struct{}{}
	} else {
		delete(s.conns, c)
	}
}

func (s *Server) Close() {
	if !atomic.CompareAndSwapInt32(&s.closed, 0, 1) {
		return
	}
	s.mu.Lock()
	for _, ln := range s.listeners {
		ln.Close()
	}
	for c := range s.conns {
		c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
}

func (s *Server) Run() error {
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: s.Cfg.LAddr.IP, Port: s.Cfg.LAddr.Port})
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.listeners = append(s.listeners, ln)
	s.mu.Unlock()
	defer ln.Close()

	la := ln.Addr().(*net.TCPAddr)
	s.log(2, "listen address: %s:%d\n", la.IP.String(), la.Port)

	for {
		c, err := ln.AcceptTCP()
		if err != nil {
			if atomic.LoadInt32(&s.closed) != 0 {
				return nil
			}
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				continue
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		c.SetNoDelay(true)
		select {
		case s.sem <- struct{}{}:
		default:
			s.log(1, "connection limit reached\n")
			c.Close()
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() { <-s.sem }()
			s.handle(c)
		}()
	}
}
