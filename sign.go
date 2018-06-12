package mar

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
)

// PrepareSignature adds a new signature header to a MAR file
// but does not sign yet. You have to call FinalizeSignature
// to actually sign the MAR file.
func (file *File) PrepareSignature(key crypto.PrivateKey, pubkey crypto.PublicKey) {
	var sig Signature
	switch pubkey.(type) {
	case *rsa.PublicKey:
		sig.AlgorithmID = SigAlgRsaPkcs1Sha384
		sig.Size = uint32(pubkey.(*rsa.PublicKey).N.BitLen() / 8)
	case *ecdsa.PublicKey:
		sig.AlgorithmID = SigAlgEcdsaSha384
		// an ecdsa signature has 2 values R and S that are
		// each the size of the curve bitsize,
		sig.Size = uint32(pubkey.(*ecdsa.PublicKey).Params().BitSize / 8 * 2)
	default:
		panic("unsupported key type")
	}
	sig.privateKey = key
	file.Signatures = append(file.Signatures, sig)
	file.SignaturesHeader.NumSignatures++
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
	for i := range file.Signatures {
		sigData, err := file.Signatures[i].privateKey.(crypto.Signer).Sign(rand.Reader, hashed[:], crypto.SHA384)
		if err != nil {
			return err
		}
		file.Signatures[i].Data = append(file.Signatures[i].Data, sigData...)
	}
	return nil
}

// MarshalForSignature returns an []byte of the data to be signed, or verified
func (file *File) MarshalForSignature() ([]byte, error) {
	file.marshalForSignature = true
	return file.Marshal()
}
