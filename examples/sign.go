package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
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
	if len(os.Args) < 3 {
		log.Fatal("usage: %s <input mar> <output mar>", os.Args[0])
	}
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
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	file.PrepareSignature(rsaKey, rsaKey.Public())
	file.PrepareSignature(ecdsaKey, ecdsaKey.Public())

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
	ioutil.WriteFile(os.Args[2], output, 0644)
	// reparse for testing, and verify signature
	err = mar.Unmarshal(output, &refile)
	if err != nil {
		log.Fatal(err)
	}

	err = refile.VerifySignature(rsaKey.Public())
	if err != nil {
		log.Fatal(err)
	}
	err = refile.VerifySignature(ecdsaKey.Public())
	if err != nil {
		log.Fatal(err)
	}
}
