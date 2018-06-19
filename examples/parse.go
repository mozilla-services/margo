package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

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
	if len(os.Args) > 2 && os.Args[2] == "json" {
		o, err := json.MarshalIndent(file, "", "    ")
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s\n", o)
	} else {
		fmt.Printf("%s\tsize=%d bytes\tsignatures=%d\tcontent=%d entries\tproduct=%q\trevision=%d\n",
			file.MarID, file.Size,
			file.SignaturesHeader.NumSignatures, len(file.Index),
			file.ProductInformation, file.Revision)
	}
	if file.Revision < 2012 {
		os.Exit(0)
	}
	validKeys, isSigned, err := file.VerifyWithFirefoxKeys()
	if err != nil {
		log.Fatal(err)
	}
	if !isSigned {
		fmt.Println("signature: no valid signature found")
	} else {
		fmt.Printf("signature: OK, valid signature from %s\n", strings.Join(validKeys, ","))
	}
}
