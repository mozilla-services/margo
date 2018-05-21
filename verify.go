package mar

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// VerifyAll checks each signature in the MAR file against the list of known
// Firefox signing keys, and returns isSigned = true if at least one signature
// validates against a known key. It also returns the names of the signing keys
// in an []string
func (file *File) VerifyAll() (keys []string, isSigned bool, err error) {
	isSigned = false
	signedBlock, err := file.MarshalForSignature()
	if err != nil {
		return
	}
	hashed := sha512.Sum384(signedBlock)
	for _, sig := range file.Signatures {
		for keyName, keyPem := range FirefoxReleasePublicKeys {
			block, _ := pem.Decode([]byte(keyPem))
			if block == nil {
				err = fmt.Errorf("failed to parse PEM block of key %q", keyName)
				return nil, false, err
			}
			pub, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				err = fmt.Errorf("failed to parse DER block of key %q: %v", keyName, err)
				return nil, false, err
			}
			rsaPub := pub.(*rsa.PublicKey)
			err = rsa.VerifyPKCS1v15(rsaPub, crypto.SHA384, hashed[:], sig.Data)
			if err == nil {
				// signature is valid
				keys = append(keys, keyName)
				isSigned = true
			}
		}
	}
	return
}
