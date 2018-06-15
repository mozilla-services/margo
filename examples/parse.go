package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"go.mozilla.org/mar"

	"gopkg.in/yaml.v2"
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
	out, err := yaml.Marshal(file)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", out)
	validKeys, isSigned, err := file.VerifyAll()
	if err != nil {
		log.Fatal(err)
	}
	if !isSigned {
		log.Fatal("signature: no valid signature found")
	} else {
		fmt.Printf("signature: OK, valid signature from %s\n", strings.Join(validKeys, ","))
	}
}
