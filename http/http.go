package tlspinhttp

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

func ListenAndServe(addr, privatekey string, handler http.Handler) error {
	l, err := tlspin.Listen("tcp", addr, privatekey)
	if err != nil {
		return err
	}
	return http.Serve(l, handler)
}
