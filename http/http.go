package tlspin_http

import (
	"net"
	"net/http"

	"github.com/nogoegst/tlspin"
)

func NewTransport(pubkey string) http.RoundTripper {
	t := http.DefaultTransport.(*http.Transport)
	t.DialTLS = func(network, addr string) (net.Conn, error) {
		return tlspin.Dial(network, addr, pubkey)
	}
	return t
}
