package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"

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
	signedBlock, err := file.MarshalForSignature()
	if err != nil {
		log.Fatal(err)
	}
	hashed := sha512.Sum384(signedBlock)
	foundValidSig := false
	for i, sig := range file.Signatures {
		for keyName, keyPem := range mar.FirefoxReleasePublicKeys {
			block, _ := pem.Decode([]byte(keyPem))
			if block == nil {
				log.Fatal("failed to parse PEM block containing the public key")
			}

			pub, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				log.Fatal("failed to parse DER encoded public key: " + err.Error())
			}
			rsaPub := pub.(*rsa.PublicKey)
			err = rsa.VerifyPKCS1v15(rsaPub, crypto.SHA384, hashed[:], sig.Data)
			if err == nil {
				fmt.Printf("* %20s\t(rsa %d bits): pass signature %d\n", keyName, rsaPub.N.BitLen(), i)
				foundValidSig = true
			} else {
				fmt.Printf("* %20s\t(rsa %d bits): failed signature %d\n", keyName, rsaPub.N.BitLen(), i)
			}
		}
	}
	if !foundValidSig {
		log.Fatal("Signature: failed")
	}
}
