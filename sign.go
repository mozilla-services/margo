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
	"encoding/base64"
	"fmt"
	"hash"
	"io"
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

// Signature output sizes in bytes
const (
	// SigAlgRsaPkcs1Sha1 is the size of a signature of type RSA-PKCS1-SHA1
	SigAlgRsaPkcs1Sha1Size = 256

	// SigAlgRsaPkcs1Sha384 is the size of a signature of type RSA-PKCS1-SHA384
	SigAlgRsaPkcs1Sha384Size = 512

	// SigAlgEcdsaP256Sha256 is the size of a signature of type ECDSA on NIST curve P256 with SHA256
	SigAlgEcdsaP256Sha256Size = 64

	// SigAlgEcdsaP384Sha384 is the size of a signature of type ECDSA on NIST curve P384 with SHA384
	SigAlgEcdsaP384Sha384Size = 96
)

// PrepareSignature adds a new signature header to a MAR file
// but does not sign yet. You have to call FinalizeSignature
// to actually sign the MAR file.
func (file *File) PrepareSignature(key crypto.PrivateKey, pubkey crypto.PublicKey) error {
	var sig Signature
 	// switch pkey := pubkey.(type) {
 	switch pubkey.(type) {
	case *rsa.PublicKey:
		sig.AlgorithmID = SigAlgRsaPkcs1Sha384
		sig.Size = 512
		// rsaKey, ok := key.(*rsa.PrivateKey)
		// if !ok {
		// 	return fmt.Errorf("RSA pubkey with non-RSA type private key of type %T\n", key)
		// }
		// rsaPubKeyFromPrivate, ok := rsaKey.Public().(*rsa.PublicKey)
		// if !ok {
		// 	return fmt.Errorf("RSA private key .Public resolves to non-RSA public key of type %T\n", rsaPubKeyFromPrivate)
		// }

		// rsaPubKeyFromPrivateSize, pKeySize := uint32(rsaPubKeyFromPrivate.Size()), uint32(pkey.Size())
		// if rsaPubKeyFromPrivateSize != pKeySize {
		// 	return fmt.Errorf("RSA pubkey size %d does not match private key size %d\n", pKeySize, rsaPubKeyFromPrivateSize)
		// }
		// if rsaPubKeyFromPrivateSize != sig.Size {
		// 	return fmt.Errorf("RSA private key size %d does not match expected key size %d\n", rsaPubKeyFromPrivateSize, sig.Size)
		// }
		// if pKeySize != sig.Size {
		// 	return fmt.Errorf("RSA pubkey size %d does not match expected key size %d\n", pKeySize, sig.Size)
		// }
	case *ecdsa.PublicKey:
		sig.AlgorithmID, sig.Size = getEcdsaInfo(pubkey.(*ecdsa.PublicKey).Params().Name)
		if sig.AlgorithmID == 0 || sig.Size == 0 {
			return fmt.Errorf("invalid ecdsa algorithm id %d size %d", sig.AlgorithmID, sig.Size)
		}
	default:
		return fmt.Errorf("unsupported private key type %T", key)
	}
	sig.privateKey = key
	file.Signatures = append(file.Signatures, sig)
	file.SignaturesHeader.NumSignatures++
	return nil
}

// FinalizeSignatures calculates RSA signatures on a MAR file
// and stores them in the Signatures slice
func (file *File) FinalizeSignatures() error {
	signableBlock, err := file.MarshalForSignature()
	if err != nil {
		return err
	}
	if len(file.Signatures) == 0 {
		return fmt.Errorf("there are no signatures to finalize")
	}
	for i := range file.Signatures {
		sig := file.Signatures[i]
		hashed, _, err := Hash(signableBlock, sig.AlgorithmID)
		if err != nil {
			return err
		}
		sigData, err := Sign(sig.privateKey, rand.Reader, hashed, sig.AlgorithmID)
		if err != nil {
			return err
		}
		hashedSize, size, expectedSize := len(hashed), len(sigData), int(getSigSizeFromID(int(sig.AlgorithmID)))
		debugPrint("Got unexpected signature size %d expected %d bytes for alg ID %d %T %d", size, expectedSize, sig.AlgorithmID, sigData, hashedSize)
		if size != expectedSize {
			return fmt.Errorf("Got unexpected signature size %d expected %d bytes for alg ID %d %T %d",
				size, expectedSize, sig.AlgorithmID, sigData, hashedSize)
		}
		file.Signatures[i].Data = append(sig.Data, sigData...)
	}
	return nil
}

// MarshalForSignature returns an []byte of the data to be signed, or verified
func (file *File) MarshalForSignature() ([]byte, error) {
	file.marshalForSignature = true
	return file.Marshal()
}

// Hash takes an input and a signature algorithm and returns its hashed value
func Hash(input []byte, sigalg uint32) (output []byte, h crypto.Hash, err error) {
	// hash the signature block using the appropriate algorithm
	var md hash.Hash
	switch sigalg {
	case SigAlgRsaPkcs1Sha1:
		md = sha1.New()
		h = crypto.SHA1
	case SigAlgEcdsaP256Sha256:
		md = sha256.New()
		h = crypto.SHA256
	case SigAlgRsaPkcs1Sha384, SigAlgEcdsaP384Sha384:
		md = sha512.New384()
		h = crypto.SHA384
	default:
		return nil, h, fmt.Errorf("unsupported signature algorithm")
	}
	md.Write(input)
	return md.Sum(nil), h, nil
}

// Sign signs digest with the private key, possibly using entropy from rand
func Sign(key crypto.PrivateKey, rand io.Reader, digest []byte, sigalg uint32) (sigData []byte, err error) {
	if _, ok := key.(crypto.Signer); !ok {
		return nil, fmt.Errorf("private key of type %T does not implement the Signer interface", key)
	}
	var h crypto.Hash
	var sigsize uint32
	switch sigalg {
	case SigAlgRsaPkcs1Sha1:
		h = crypto.SHA1
	case SigAlgEcdsaP256Sha256:
		_, sigsize = getEcdsaInfo(elliptic.P256().Params().Name)
		h = crypto.SHA256
	case SigAlgRsaPkcs1Sha384, SigAlgEcdsaP384Sha384:
		_, sigsize = getEcdsaInfo(elliptic.P384().Params().Name)
		if sigsize == 0 {

		}
		h = crypto.SHA384
	default:
		return nil, fmt.Errorf("unsupported signature algorithm")
	}
	// call the signer interface of the private key to sign the hash
	sigData, err = key.(crypto.Signer).Sign(rand, digest, h)
	debugPrint("sigData len %d for alg ID: %d", len(sigData), sigalg)
	if err != nil {
		return nil, err
	}
	switch sigalg {
	case SigAlgRsaPkcs1Sha1, SigAlgRsaPkcs1Sha384:
		// Signature is already in the PKCSv1_15 format so return it as is
		return sigData, nil
	case SigAlgEcdsaP256Sha256, SigAlgEcdsaP384Sha384:
		// when using an ecdsa key, the Sign() interface returns an ASN.1 encoded signature
		// which we need to parse and convert to its R||S form
		if int(sigsize) < 64 {
			return nil, fmt.Errorf("signature size of %d is too small for signature data", sigsize)
		}
		return convertAsn1EcdsaToRS(sigData, int(sigsize))
	}
	return nil, fmt.Errorf("unsupported key type %T", key)
}

type ecdsaSignature struct {
	R, S *big.Int
}

func convertAsn1EcdsaToRS(sigData []byte, sigLen int) ([]byte, error) {
	debugPrint("asn1.ecdsa: %s\n", base64.StdEncoding.EncodeToString(sigData))
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

func isRSAAlgID(algID uint32) bool {
	return algID == SigAlgRsaPkcs1Sha1 || algID == SigAlgRsaPkcs1Sha384
}

func getEcdsaInfo(curve string) (uint32, uint32) {
	switch curve {
	case elliptic.P256().Params().Name:
		return SigAlgEcdsaP256Sha256, getSigSizeFromID(SigAlgEcdsaP256Sha256)
	case elliptic.P384().Params().Name:
		return SigAlgEcdsaP384Sha384, getSigSizeFromID(SigAlgEcdsaP384Sha384)
	default:
		return 0, 0
	}
}

func getSigAlgNameFromID(id uint32) string {
	switch id {
	case SigAlgRsaPkcs1Sha1:
		return "RSA-PKCS1v15-SHA1"
	case SigAlgRsaPkcs1Sha384:
		return "RSA-PKCS1v15-SHA384"
	case SigAlgEcdsaP256Sha256:
		return "ECDSA-P256-SHA256"
	case SigAlgEcdsaP384Sha384:
		return "ECDSA-P384-SHA384"
	}
	return "unknown"
}

func getSigSizeFromID(id int) uint32 {
	switch id {
	case SigAlgRsaPkcs1Sha1:
		return SigAlgRsaPkcs1Sha1Size
	case SigAlgRsaPkcs1Sha384:
		return SigAlgRsaPkcs1Sha384Size
	case SigAlgEcdsaP256Sha256:
		return SigAlgEcdsaP256Sha256Size
	case SigAlgEcdsaP384Sha384:
		return SigAlgEcdsaP384Sha384Size
	}
	return 0
}
