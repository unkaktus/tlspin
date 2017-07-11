package tlspin

import (
	"net"
	"net/http"
)

func NewTransport(pubkey string) http.RoundTripper {
	t := http.DefaultTransport.(*http.Transport)
	t.DialTLS = func(network, addr string) (net.Conn, error) {
		return Dial(network, addr, pubkey)
	}
	return t
}
