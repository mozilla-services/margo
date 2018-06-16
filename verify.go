package mar

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"hash"
	"math/big"
)

// VerifySignature attempts to verify signatures in the MAR file using
// the provided public key until one of them passes. A valid signature
// is indicated by returning a nil error.
func (file *File) VerifySignature(key crypto.PublicKey) error {
	signedBlock, err := file.MarshalForSignature()
	if err != nil {
		return err
	}
	for _, sig := range file.Signatures {
		switch key.(type) {
		case *rsa.PublicKey:
			switch sig.AlgorithmID {
			case SigAlgRsaPkcs1Sha1:
				hashed := sha1.Sum(signedBlock)
				err = rsa.VerifyPKCS1v15(key.(*rsa.PublicKey), crypto.SHA1, hashed[:], sig.Data)
				if err == nil {
					// signature is valid, return
					debugPrint("found valid %s signature\n", sig.Algorithm)
					return nil
				}
			case SigAlgRsaPkcs1Sha384:
				hashed := sha512.Sum384(signedBlock)
				err = rsa.VerifyPKCS1v15(key.(*rsa.PublicKey), crypto.SHA384, hashed[:], sig.Data)
				if err == nil {
					debugPrint("found valid %s signature\n", sig.Algorithm)
					return nil
				}
			default:
				// ignore other signature types that may be using a non-rsa key
				continue
			}
		case *ecdsa.PublicKey:
			var md hash.Hash
			switch sig.AlgorithmID {
			case SigAlgEcdsaP256Sha256:
				md = sha256.New()
			case SigAlgEcdsaP384Sha384:
				md = sha512.New384()
			default:
				// ignore other signature types that may be using a non-rsa key
				continue
			}
			md.Write(signedBlock)
			r, s := new(big.Int), new(big.Int)
			r.SetBytes(sig.Data[:len(sig.Data)/2])
			s.SetBytes(sig.Data[len(sig.Data)/2:])
			if ecdsa.Verify(key.(*ecdsa.PublicKey), md.Sum(nil), r, s) {
				debugPrint("found valid %s signature\n", sig.Algorithm)
				return nil
			}
		default:
			return fmt.Errorf("unknown public key type")
		}
	}
	return fmt.Errorf("no valid signature found")
}

// VerifyWithFirefoxKeys checks each signature in the MAR file against the list of known
// Firefox signing keys, and returns isSigned = true if at least one signature
// validates against a known key. It also returns the names of the signing keys
// in an []string
func (file *File) VerifyWithFirefoxKeys() (keys []string, isSigned bool, err error) {
	isSigned = false
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
		err = file.VerifySignature(pub)
		if err == nil {
			// signature is valid
			keys = append(keys, keyName)
			isSigned = true
		} else {
			debugPrint("signature verification failed with firefox key %q\n", keyName)
		}
	}
	return
}
