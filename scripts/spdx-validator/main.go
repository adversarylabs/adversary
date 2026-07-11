package main

import (
	"fmt"
	"os"

	spdxjson "github.com/spdx/tools-golang/json"
	"github.com/spdx/tools-golang/spdxlib"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: spdx-validator <document>")
		os.Exit(2)
	}
	f, err := os.Open(os.Args[1])
	if err != nil {
		panic(err)
	}
	defer f.Close()
	doc, err := spdxjson.Read(f)
	if err != nil {
		panic(err)
	}
	if err := spdxlib.ValidateDocument(doc); err != nil {
		panic(err)
	}
}
