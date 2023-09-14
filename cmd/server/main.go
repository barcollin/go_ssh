package main

import (
	"fmt"
	"log"
	"os"

	ssh "github.com/barcollin/go_ssh"
)

func main() {
	var (
		err error
	)

	authorizedKeysBytes, err := os.ReadFile("mykey.pub")
	if err != nil {
		log.Fatalf("Failed to load authorized_keys, err : %v", err)
	}

	privateKey, err := os.ReadFile("server.pem")
	if err != nil {
		log.Fatalf("Failed to load server.pem, err: %v", err)
	}

	if err = ssh.StartServer(privateKey, authorizedKeysBytes); err != nil {
		fmt.Printf("Error: %s\n", err)
		os.Exit(1)
	}

}
