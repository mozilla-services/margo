package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"

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
	jsonOut, err := json.MarshalIndent(file, "", "    ")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", jsonOut)
}
