package mar

import (
	"crypto/x509"
	"encoding/pem"
	"log"
	"testing"
)

func TestFirefoxKeys(t *testing.T) {
	testMar := New()
	testMar.AddContent([]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), "/foo/bar", 0600)

	// add the test rsa key to the list of firefox keys
	publicKeyDer, err := x509.MarshalPKIXPublicKey(&rsa2048Key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicKeyBlock := pem.Block{
		Type:    "PUBLIC KEY",
		Headers: nil,
		Bytes:   publicKeyDer,
	}
	publicKeyPem := string(pem.EncodeToMemory(&publicKeyBlock))
	FirefoxReleasePublicKeys["unit_test"] = publicKeyPem

	testMar.PrepareSignature(rsa2048Key, rsa2048Key.Public())
	testMar.FinalizeSignatures()

	validKeys, isSigned, err := testMar.VerifyWithFirefoxKeys()
	if err != nil {
		log.Fatal(err)
	}
	if !isSigned {
		t.Fatal("expected signed MAR file but didn't get one")
	}
	if len(validKeys) != 1 || validKeys[0] != "unit_test" {
		t.Fatal("expected signature from 'unit_test' key but didn't get one")
	}
}
