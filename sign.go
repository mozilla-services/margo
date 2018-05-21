package mar

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
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
	// the total size of a signature block is the original file minus the signature data
	var sigDataSize uint32
	for _, sig := range file.Signatures {
		sigDataSize += sig.Size
	}
	output := make([]byte, file.SignaturesHeader.FileSize-uint64(sigDataSize))

	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, []byte(file.MarID))
	if err != nil {
		return nil, err
	}
	err = binary.Write(buf, binary.BigEndian, file.OffsetToIndex)
	if err != nil {
		return nil, err
	}
	err = binary.Write(buf, binary.BigEndian, file.SignaturesHeader)
	if err != nil {
		return nil, err
	}
	for _, sig := range file.Signatures {
		err = binary.Write(buf, binary.BigEndian, sig.AlgorithmID)
		if err != nil {
			return nil, err
		}
		err = binary.Write(buf, binary.BigEndian, sig.Size)
		if err != nil {
			return nil, err
		}
	}
	err = binary.Write(buf, binary.BigEndian, file.AdditionalSectionsHeader)
	if err != nil {
		return nil, err
	}
	for _, as := range file.AdditionalSections {
		err = binary.Write(buf, binary.BigEndian, as.BlockSize)
		if err != nil {
			return nil, err
		}
		err = binary.Write(buf, binary.BigEndian, as.BlockID)
		if err != nil {
			return nil, err
		}
		err = binary.Write(buf, binary.BigEndian, as.Data)
		if err != nil {
			return nil, err
		}
	}
	// insert the first section at the beginning of the file
	copy(output[0:buf.Len()], buf.Bytes())

	// we need to marshal the content according to the index
	idxBuf := new(bytes.Buffer)
	err = binary.Write(idxBuf, binary.BigEndian, file.IndexHeader)
	if err != nil {
		return nil, err
	}
	for _, idx := range file.Index {
		err = binary.Write(idxBuf, binary.BigEndian, idx.OffsetToContent)
		if err != nil {
			return nil, err
		}
		err = binary.Write(idxBuf, binary.BigEndian, idx.Size)
		if err != nil {
			return nil, err
		}
		err = binary.Write(idxBuf, binary.BigEndian, idx.Flags)
		if err != nil {
			return nil, err
		}
		err = binary.Write(idxBuf, binary.BigEndian, []byte(idx.FileName))
		if err != nil {
			return nil, err
		}
		_, err = idxBuf.Write([]byte("\x00"))
		if err != nil {
			return nil, err
		}
		// copy the content in the right position earlier in the file
		// since we don't signatures, we remove their size from the offsets
		copy(output[idx.OffsetToContent-sigDataSize:idx.OffsetToContent+idx.Size-sigDataSize], file.Content[idx.FileName].Data)
	}
	if uint32(idxBuf.Len()) != file.IndexHeader.Size+IndexHeaderLen {
		return nil, fmt.Errorf("marshalled index has size %d when size %d was expected", idxBuf.Len(), file.IndexHeader.Size)
	}
	// append the index to the end of the output
	copy(output[file.OffsetToIndex-sigDataSize:file.OffsetToIndex+uint32(idxBuf.Len())-sigDataSize], idxBuf.Bytes())

	return output, nil
}
