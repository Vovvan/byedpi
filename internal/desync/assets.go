package desync

import _ "embed"

//go:embed assets/tls.bin
var fakeTLS []byte

//go:embed assets/http.bin
var fakeHTTP []byte

//go:embed assets/udp.bin
var fakeUDP []byte

func FakeTLS() []byte  { return fakeTLS }
func FakeHTTP() []byte { return fakeHTTP }
func FakeUDP() []byte  { return fakeUDP }
