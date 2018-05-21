package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"go.mozilla.org/mar"
)

func main() {
	var file mar.File
	input, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		log.Fatal("Error while opening fd", err)
	}
	err = mar.Unmarshal(input, &file)
	if err != nil {
		log.Fatal(err)
	}
	validKeys, isSigned, err := file.VerifyAll()
	if err != nil {
		log.Fatal(err)
	}
	if !isSigned {
		log.Fatal("Signature: no valid signature found")
	} else {
		fmt.Printf("Signature: OK, valid signature from %s\n", strings.Join(validKeys, ","))
	}
}
