package main

import (
	"flag"
	"log"

	"github.com/nogoegst/tlspin"
	"github.com/nogoegst/tlspin/util"
)

func main() {
	flag.Parse()
	if len(flag.Args()) == 0 {
		log.Fatalf("address not specified")
	}
	addr := flag.Args()[0]
	conn, keydigest, err := tlspin.InitDial("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	conn.Close()
	log.Printf("%s", tlspinutil.EncodeKey(keydigest))
}
