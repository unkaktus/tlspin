// gen.go - generate keypair for tlspin.
//
// To the extent possible under law, Ivan Markin has waived all copyright
// and related or neighboring rights to tlspin, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package main

import (
	"fmt"
	"log"

	"github.com/nogoegst/tlspin/util"
)

func main() {
	sk, err := tlspinutil.GeneratePrivateKey()
	if err != nil {
		log.Fatal(err)
	}
	pk, err := tlspinutil.PublicKey(sk)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("private key: %v\n", sk)
	fmt.Printf("public  key: %v\n", pk)
}
