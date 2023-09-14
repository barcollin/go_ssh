package main

import (
	"fmt"
	"os"
)

func main() {
	var (
		privateKey []byte
		publicKey  []byte
		err        error
	)

	if privateKey, plublicKey, err = ssh.GenerateKeys(); err != nil {
		fmt.Printf("Error: %s\n", err)
		os.Exit(1)
	}

	if err = os.WriteFile("mykey.pem", privateKey, 0600); err != nil {
		fmt.Printf("Error: %s\n", err)
		os.Exit(1)
	}

	if err = os.WriteFile("mykey.pub", publicKey, 0600); err != nil {
		fmt.Printf("Error: %s\n", err)
		os.Exit(1)
	}
}
