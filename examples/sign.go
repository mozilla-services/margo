package main

import (
	"crypto/rand"
	"crypto/rsa"
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
	signedBlock, err := file.MarshalForSignature()
	if err != nil {
		log.Fatal(err)
	}

	// Add both keys for signature, then finalize
	rsaKey1, err := rsa.GenerateKey(rand.Reader, 512)
	if err != nil {
		log.Fatal(err)
	}
	rsaKey2, err := rsa.GenerateKey(rand.Reader, 512)
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

	// reparse for testing, and verify signature
	err = mar.Unmarshal(input, &refile)
	if err != nil {
		log.Fatal(err)
	}

}
