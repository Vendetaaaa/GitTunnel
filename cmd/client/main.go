package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
)

type subdomainRequestPayload struct {
	Subdomain string
}

type subdomainReplyPayload struct {
	Subdomain string
}

func loadPrivateKey(path string) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(data)
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func requestSubdomain(client *ssh.Client, want string) (string, error) {
	payload := subdomainRequestPayload{Subdomain: want}
	ok, reply, err := client.SendRequest("gittunnel-subdomain", true, ssh.Marshal(&payload))
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("subdomain request rejected by server")
	}
	var res subdomainReplyPayload
	if err := ssh.Unmarshal(reply, &res); err != nil {
		return "", err
	}
	return res.Subdomain, nil
}

func main() {
	serverAddr := envOrDefault("GITTUNNEL_SERVER", "127.0.0.1:2222")
	localTarget := envOrDefault("GITTUNNEL_LOCAL", "127.0.0.1:3000")
	user := envOrDefault("GITTUNNEL_USER", "tunnel")
	keyPath := envOrDefault("GITTUNNEL_KEY", os.Getenv("HOME")+"/.ssh/id_rsa")
	wantSubdomain := os.Getenv("GITTUNNEL_SUBDOMAIN")
	baseDomain := envOrDefault("GITTUNNEL_BASE_DOMAIN", "tunnels.example.com")

	signer, err := loadPrivateKey(keyPath)
	if err != nil {
		log.Fatalf("failed to load private key %s: %v", keyPath, err)
	}

	config := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := ssh.Dial("tcp", serverAddr, config)
	if err != nil {
		log.Fatalf("failed to connect to gittunnel server %s: %v", serverAddr, err)
	}
	defer client.Close()

	subdomain, err := requestSubdomain(client, wantSubdomain)
	if err != nil {
		log.Fatalf("failed to acquire subdomain: %v", err)
	}

	remoteListener, err := client.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatalf("failed to establish remote listener: %v", err)
	}
	defer remoteListener.Close()

	log.Printf("tunnel established: https://%s.%s -> %s", subdomain, baseDomain, localTarget)

	for {
		remoteConn, err := remoteListener.Accept()
		if err != nil {
			log.Printf("tunnel closed: %v", err)
			return
		}
		go handleTunnelConn(remoteConn, localTarget)
	}
}

func handleTunnelConn(remoteConn net.Conn, localTarget string) {
	defer remoteConn.Close()

	localConn, err := net.Dial("tcp", localTarget)
	if err != nil {
		log.Printf("failed to reach local target %s: %v", localTarget, err)
		return
	}
	defer localConn.Close()

	done := make(chan struct{}, 2)

	go func() {
		io.Copy(localConn, remoteConn)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(remoteConn, localConn)
		done <- struct{}{}
	}()

	<-done
}
