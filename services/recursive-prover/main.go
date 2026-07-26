package main

import (
	"log"
	"net/http"
	"os"
)

func main() {
	address := os.Getenv("RECURSIVE_PROVER_ADDRESS")
	if address == "" {
		address = "127.0.0.1:8090"
	}
	log.Printf(
		"recursive prover API listening on %s; cryptographic engine is fail-closed",
		address,
	)
	if err := http.ListenAndServe(
		address,
		NewProofServer(UnavailableEngine{}, 2),
	); err != nil {
		log.Fatal(err)
	}
}
