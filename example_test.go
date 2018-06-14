package mar_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"

	"go.mozilla.org/mar"
)

func Example() {
	inputMar := miniMar

	// flush the signatures if any exists
	inputMar.SignaturesHeader.NumSignatures = uint32(0)
	inputMar.Signatures = nil

	// make a new rsa key and add it for signature
	rsaPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("rsa key generation failed with: %v", err)
	}
	inputMar.PrepareSignature(rsaPrivKey, rsaPrivKey.Public())

	// make a new ecdsa key and add it for signature
	ecdsaPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("ecdsa key generation failed with: %v", err)
	}
	inputMar.PrepareSignature(ecdsaPrivKey, ecdsaPrivKey.Public())

	// once both keys are added to the file, finalize the signature
	err = inputMar.FinalizeSignatures()
	if err != nil {
		log.Fatalf("mar signature failed with error: %v", err)
	}

	// write out the MAR file
	outputMar, err := inputMar.Marshal()
	if err != nil {
		log.Fatalf("mar marshalling failed with error: %v", err)
	}

	// reparse the MAR to make sure it goes through fine
	var reparsedMar mar.File
	err = mar.Unmarshal(outputMar, &reparsedMar)
	if err != nil {
		log.Fatalf("mar unmarshalling failed with error: %v", err)
	}

	fmt.Printf("MAR file signed and parsed without error")

	// Output: MAR file signed and parsed without error
}

var miniMar = mar.File{
	MarID:         "MAR1",
	OffsetToIndex: 1664,
	Content: map[string]mar.Entry{
		"/foo/bar": mar.Entry{
			Data:         []byte("aaaaaaaaaaaaaaaaaaaaa"),
			IsCompressed: false,
		},
	},
	IndexHeader: mar.IndexHeader{
		Size: 21,
	},
	Index: []mar.IndexEntry{
		mar.IndexEntry{
			mar.IndexEntryHeader{
				OffsetToContent: 400,
				Size:            21,
				Flags:           600,
			},
			"/foo/bar",
		},
	},
}
