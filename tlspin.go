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
	"crypto/x509"
	"errors"
	"net"

	util "github.com/nogoegst/tlspin/util"
	"golang.org/x/crypto/blake2b"
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
			//tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
		Certificates: []tls.Certificate{*tlsCert},
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

func Dial(network, addr, publickey string) (net.Conn, error) {
	pk, err := util.DecodeKey(publickey)
	if err != nil {
		return nil, err
	}
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	c, err := tls.Dial(network, addr, tlsConfig)
	if err != nil {
		return nil, err
	}
	connstate := c.ConnectionState()
	keyValid := false
	for _, peercert := range connstate.PeerCertificates {
		der, _ := x509.MarshalPKIXPublicKey(peercert.PublicKey)
		hash := blake2b.Sum256(der)
		if subtle.ConstantTimeCompare(hash[:], pk) == 1 {
			keyValid = true
		}
	}
	if !keyValid {
		return nil, errors.New("invalid key")
	}
	return c, nil
}
