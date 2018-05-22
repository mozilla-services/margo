package mar

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
)

// PrepareSignature adds a new signature header to a MAR file
// but does not sign yet. You have to call FinalizeSignature
// to actually sign the MAR file.
func (file *File) PrepareSignature(key *rsa.PrivateKey) {
	var sig Signature
	sig.AlgorithmID = SigAlgRsaPkcs1Sha384
	sig.Size = uint32(key.N.BitLen() / 8)
	sig.privateKey = key
	file.Signatures = append(file.Signatures, sig)
	return
}

// FinalizeSignatures calculates RSA signatures on a MAR file
// and stores them in the Signatures slice
func (file *File) FinalizeSignatures() error {
	signableBlock, err := file.MarshalForSignature()
	if err != nil {
		return err
	}
	hashed := sha512.Sum384(signableBlock)
	for i, sig := range file.Signatures {
		file.Signatures[i].Data, err = rsa.SignPKCS1v15(rand.Reader, sig.privateKey, crypto.SHA384, hashed[:])
		if err != nil {
			return err
		}
	}
	return nil
}

// MarshalForSignature returns an []byte of the data to be signed, or verified
func (file *File) MarshalForSignature() ([]byte, error) {
	file.marshalForSignature = true
	return file.Marshal()
}
