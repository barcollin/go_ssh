package ssh

import (
	"fmt"
	"log"
	"net"

	"golang.org/x/crypto/ssh"
)

func StartServer(privateKey []byte, authorizedKeys []byte) error {
	authorizedKeysMap := map[string]bool{}

	for len(authorizedKeys) > 0 {
		pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(authorizedKeys)

		if err != nil {
			return fmt.Errorf("Parse Authorized keys error: %s", err)
		}

		authorizedKeysMap[string(pubKey.Marshal())] = true
		authorizedKeys = rest
	}

	config := &ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			if authorizedKeysMap[string(pubKey.Marshal())] {
				return &ssh.Permissions{
					Extensions: map[string]string{
						"pubkey-fp": ssh.FingerprintSHA256(pubKey),
					},
				}, nil
			}
			return nil, fmt.Errorf("Unknown public key for %q", c.User())
		},
	}

	private, err := ssh.ParsePrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("Failed to parse private key %s", err)
	}

	config.AddHostKey(private)

	listener, err := net.Listen("tcp", "0.0.0.0:2022")
	if err != nil {
		return fmt.Errorf("Failed to listen for connection %s", err)
	}

	nConn, err := listener.Accept()
	if err != nil {
		return fmt.Errorf("Failed to accept incoming connection %s", err)
	}

	conn, _, _, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		return fmt.Errorf("Failed to accept incoming connection %s", err)
	}

	log.Printf("logged in with key %s", conn.Permissions.Extensions["pubkey-fp"])
	return nil

}
