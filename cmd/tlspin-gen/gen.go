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
