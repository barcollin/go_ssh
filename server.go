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
					// Record the public key used for authentication.
					Extensions: map[string]string{
						"pubkey-fp": ssh.FingerprintSHA256(pubKey),
					},
				}, nil
			}
			return nil, fmt.Errorf("unknown public key for %q", c.User())
		},
	}

	private, err := ssh.ParsePrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("ParsePrivateKey error: %s", err)
	}

	config.AddHostKey(private)

	// accepted.
	listener, err := net.Listen("tcp", "0.0.0.0:2022")
	if err != nil {
		return fmt.Errorf("Listen error: %s", err)
	}

	for {

		nConn, err := listener.Accept()
		if err != nil {
			fmt.Printf("Listener accept error: %s\n", err)
		}

		conn, chans, reqs, err := ssh.NewServerConn(nConn, config)
		if err != nil {
			fmt.Printf("NewServerConn error: %s\n", err)
		}
		if conn != nil && conn.Permissions != nil {
			log.Printf("logged in with key %s", conn.Permissions.Extensions["pubkey-fp"])
		}

		// The incoming Request channel must be serviced.
		go ssh.DiscardRequests(reqs)

		go handleConnection(conn, chans)

	}

}

func handleConnection(conn *ssh.ServerConn, chans <-chan ssh.NewChannel) {
	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}
		_, requests, err := newChannel.Accept()
		if err != nil {
			fmt.Printf("Could not accept channel: %v", err)
		}

		go func(in <-chan *ssh.Request) {
			for req := range in {
				fmt.Printf("Request Type made by client: %s\n", req.Type)
				switch req.Type {
				case "shell":
					req.Reply(true, nil)
				case "pty-req":
				default:
					req.Reply(false, nil)
				}
			}
		}(requests)
	}
}
