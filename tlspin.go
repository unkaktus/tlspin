// tlspin.go - reduce TLS to keypinning.
//
// To the extent possible under law, Ivan Markin has waived all copyright
// and related or neighboring rights to tlspin, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package tlspin

import (
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"net"

	util "github.com/nogoegst/tlspin/util"
)

func TLSConfig(privatekey string) (*tls.Config, error) {
	tlsCert, err := util.GenerateCertificate(privatekey)
	if err != nil {
		return nil, err
	}
	config := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.X25519},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
		Certificates: []tls.Certificate{*tlsCert},
		NextProtos: []string{
			"h2",
		},
	}
	return config, nil
}

func Listen(network, addr, privatekey string) (net.Listener, error) {
	tlsConfig, err := TLSConfig(privatekey)
	if err != nil {
		return nil, err
	}
	return tls.Listen(network, addr, tlsConfig)
}

func DialWithDialer(dialer *net.Dialer, network, addr, publickey string) (net.Conn, error) {
	var pk []byte
	verifyKey := true
	if publickey == "whateverkey" {
		verifyKey = false
	} else {
		var err error
		pk, err = util.DecodeKey(publickey)
		if err != nil {
			return nil, err
		}
	}
	c, keydigest, err := util.InitDialWithDialer(dialer, network, addr)
	if err != nil {
		return c, nil
	}
	if !verifyKey {
		return c, nil
	}
	if subtle.ConstantTimeCompare(keydigest, pk) != 1 {
		return nil, errors.New("invalid key")
	}
	return c, nil
}

func Dial(network, addr, publickey string) (net.Conn, error) {
	return DialWithDialer(new(net.Dialer), network, addr, publickey)
}
