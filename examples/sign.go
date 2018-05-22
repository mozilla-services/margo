package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"go.mozilla.org/mar"
)

func main() {
	var file, refile mar.File
	input, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		log.Fatal("Error while opening fd", err)
	}
	err = mar.Unmarshal(input, &file)
	if err != nil {
		log.Fatal(err)
	}

	// flush the signatures, we'll make new ones
	file.SignaturesHeader.NumSignatures = uint32(0)
	file.Signatures = nil

	// Add both keys for signature, then finalize
	rsaKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	rsaKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	file.PrepareSignature(rsaKey1)
	file.PrepareSignature(rsaKey2)

	// once both keys are added to the file, finalize the signature
	err = file.FinalizeSignatures()
	if err != nil {
		log.Fatal(err)
	}

	// write out the MAR file
	output, err := file.Marshal()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("--- MAR file has been resigned ---")
	ioutil.WriteFile("/tmp/resigned.mar", output, 0644)
	// reparse for testing, and verify signature
	err = mar.Unmarshal(output, &refile)
	if err != nil {
		log.Fatal(err)
	}
}
