// http.go - tlspin supplementary for HTTP.
//
// To the extent possible under law, Ivan Markin has waived all copyright
// and related or neighboring rights to tlspin, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package tlspinhttp

import (
	"crypto/tls"
	"net/http"

	"github.com/nogoegst/tlspin"
	"golang.org/x/net/http2"
)

func NewTransport(pubkey string) (http.RoundTripper, error) {
	var err error
	t := http.DefaultTransport.(*http.Transport)
	t.TLSClientConfig, err = tlspin.TLSClientConfig(pubkey)
	if err != nil {
		return nil, err
	}
	err = http2.ConfigureTransport(t)
	if err != nil {
		return nil, err
	}
	t.TLSClientConfig.InsecureSkipVerify = true
	return t, nil
}

func ListenAndServe(addr, privatekey string, handler http.Handler) error {
	tlsConfig, err := tlspin.TLSServerConfig(privatekey)
	if err != nil {
		return err
	}
	tlsConfig.NextProtos = []string{"h2"}
	l, err := tls.Listen("tcp", addr, tlsConfig)
	if err != nil {
		return err
	}
	return http.Serve(l, handler)
}
