package mar

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"hash"
	"math/big"
)

// Signature types
const (
	// SigAlgRsaPkcs1Sha1 is the ID of a signature of type RSA-PKCS1-SHA1
	SigAlgRsaPkcs1Sha1 = 1

	// SigAlgRsaPkcs1Sha384 is the ID of a signature of type RSA-PKCS1-SHA384
	SigAlgRsaPkcs1Sha384 = 2

	// SigAlgEcdsaP256Sha256 is the ID of a signature of type ECDSA on NIST curve P256 with SHA256
	SigAlgEcdsaP256Sha256 = 3

	// SigAlgEcdsaP384Sha384 is the ID of a signature of type ECDSA on NIST curve P384 with SHA384
	SigAlgEcdsaP384Sha384 = 4
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
		sig.AlgorithmID, sig.Size = getEcdsaInfo(pubkey.(*ecdsa.PublicKey).Params().Name)
		if sig.AlgorithmID == 0 || sig.Size == 0 {
			panic("unsupported key type")
		}
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
	for i := range file.Signatures {
		// hash the signature block using the appropriate algorithm
		var md hash.Hash
		switch file.Signatures[i].AlgorithmID {
		case SigAlgRsaPkcs1Sha1:
			md = sha1.New()
		case SigAlgEcdsaP256Sha256:
			md = sha256.New()
		case SigAlgRsaPkcs1Sha384, SigAlgEcdsaP384Sha384:
			md = sha512.New384()
		}
		md.Write(signableBlock)

		// call the signer interface of the private key to sign the hash
		sigData, err := file.Signatures[i].privateKey.(crypto.Signer).Sign(
			rand.Reader, md.Sum(nil), crypto.SHA384)
		if err != nil {
			return err
		}

		// write the signature into the mar file
		switch file.Signatures[i].privateKey.(type) {
		case *ecdsa.PrivateKey:
			// when using an ecdsa key, the Sign() interface returns an ASN.1 encoded signature
			// which we need to parse and convert to its R||S form
			sigData, err := convertAsn1EcdsaToRS(sigData, int(file.Signatures[i].Size))
			if err != nil {
				return err
			}
			file.Signatures[i].Data = append(file.Signatures[i].Data, sigData...)
		case *rsa.PrivateKey:
			// when using an rsa key, the Sign() interface returns a PKCS1 v1.5 signature that
			// we directly insert into the MAR file.
			file.Signatures[i].Data = append(file.Signatures[i].Data, sigData...)
		}
	}
	return nil
}

// MarshalForSignature returns an []byte of the data to be signed, or verified
func (file *File) MarshalForSignature() ([]byte, error) {
	file.marshalForSignature = true
	return file.Marshal()
}

type ecdsaSignature struct {
	R, S *big.Int
}

func convertAsn1EcdsaToRS(sigData []byte, sigLen int) ([]byte, error) {
	var ecdsaSig ecdsaSignature
	_, err := asn1.Unmarshal(sigData, &ecdsaSig)
	if err != nil {
		return nil, err
	}
	// write R and S into a slice of len
	// both R and S are zero-padded to the left to be exactly
	// len/2 in length
	Rstart := (sigLen / 2) - len(ecdsaSig.R.Bytes())
	Rend := (sigLen / 2)
	Sstart := sigLen - len(ecdsaSig.S.Bytes())
	Send := sigLen
	rs := make([]byte, sigLen)
	copy(rs[Rstart:Rend], ecdsaSig.R.Bytes())
	copy(rs[Sstart:Send], ecdsaSig.S.Bytes())
	return rs, nil
}

func getEcdsaInfo(curve string) (uint32, uint32) {
	switch curve {
	case elliptic.P256().Params().Name:
		return SigAlgEcdsaP256Sha256, 64
	case elliptic.P384().Params().Name:
		return SigAlgEcdsaP384Sha384, 96
	default:
		return 0, 0
	}
}
