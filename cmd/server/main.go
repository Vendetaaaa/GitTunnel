package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
)

type tcpIPForwardPayload struct {
	Addr string
	Port uint32
}

type tcpIPForwardPayloadReply struct {
	Port uint32
}

type forwardedTCPPayload struct {
	Addr       string
	Port       uint32
	OriginAddr string
	OriginPort uint32
}

type subdomainRequestPayload struct {
	Subdomain string
}

type subdomainReplyPayload struct {
	Subdomain string
}

type forwardState struct {
	mu               sync.Mutex
	listeners        map[string]net.Listener
	pendingSubdomain string
	subdomains       map[string]bool
}

func newForwardState() *forwardState {
	return &forwardState{
		listeners:  make(map[string]net.Listener),
		subdomains: make(map[string]bool),
	}
}

type routeEntry struct {
	sshConn *ssh.ServerConn
	addr    string
	port    uint32
}

type router struct {
	mu     sync.Mutex
	routes map[string]*routeEntry
}

func newRouter() *router {
	return &router{routes: make(map[string]*routeEntry)}
}

func (r *router) reserve(subdomain string, sshConn *ssh.ServerConn) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.routes[subdomain]; exists {
		return false
	}
	r.routes[subdomain] = &routeEntry{sshConn: sshConn}
	return true
}

func (r *router) confirm(subdomain, addr string, port uint32) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if entry, ok := r.routes[subdomain]; ok {
		entry.addr = addr
		entry.port = port
	}
}

func (r *router) unregister(subdomain string) {
	r.mu.Lock()
	delete(r.routes, subdomain)
	r.mu.Unlock()
}

func (r *router) lookup(subdomain string) (*routeEntry, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.routes[subdomain]
	if !ok || entry.port == 0 {
		return nil, false
	}
	return entry, true
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func generateHostKey() (ssh.Signer, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(key)
}

func loadAuthorizedKeys(path string) (map[string]bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	result := make(map[string]bool)
	rest := data
	for len(rest) > 0 {
		pubKey, _, _, tail, err := ssh.ParseAuthorizedKey(rest)
		if err != nil {
			break
		}
		result[string(pubKey.Marshal())] = true
		rest = tail
	}
	return result, nil
}

func randomSubdomain() string {
	buf := make([]byte, 5)
	rand.Read(buf)
	return hex.EncodeToString(buf)
}

func randomPort() uint32 {
	buf := make([]byte, 2)
	rand.Read(buf)
	port := binary.BigEndian.Uint16(buf)
	if port == 0 {
		port = 1
	}
	return uint32(port)
}

func main() {
	listenAddr := envOrDefault("GITTUNNEL_LISTEN", "0.0.0.0:2222")
	httpListenAddr := envOrDefault("GITTUNNEL_HTTP_LISTEN", "0.0.0.0:8080")
	baseDomain := envOrDefault("GITTUNNEL_BASE_DOMAIN", "tunnels.example.com")
	authKeysPath := envOrDefault("GITTUNNEL_AUTHORIZED_KEYS", "authorized_keys")

	authKeys, err := loadAuthorizedKeys(authKeysPath)
	if err != nil {
		log.Fatalf("failed to load authorized keys: %v", err)
	}

	hostKey, err := generateHostKey()
	if err != nil {
		log.Fatalf("failed to generate host key: %v", err)
	}

	config := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if authKeys[string(key.Marshal())] {
				return &ssh.Permissions{}, nil
			}
			return nil, fmt.Errorf("unauthorized public key for user %q", conn.User())
		},
	}
	config.AddHostKey(hostKey)

	reg := newRouter()

	go runHTTPRouter(httpListenAddr, baseDomain, reg)

	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("failed to listen on %s: %v", listenAddr, err)
	}
	log.Printf("gittunnel ssh control listening on %s", listenAddr)
	log.Printf("gittunnel http router listening on %s (base domain %s)", httpListenAddr, baseDomain)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		go handleConn(conn, config, reg)
	}
}

func handleConn(conn net.Conn, config *ssh.ServerConfig, reg *router) {
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		conn.Close()
		return
	}
	defer sshConn.Close()

	log.Printf("client authenticated: %s (%s)", sshConn.RemoteAddr(), sshConn.User())

	state := newForwardState()
	go handleChannels(chans)
	go handleGlobalRequests(reqs, sshConn, state, reg)

	sshConn.Wait()

	state.mu.Lock()
	for key, l := range state.listeners {
		l.Close()
		delete(state.listeners, key)
	}
	for subdomain := range state.subdomains {
		reg.unregister(subdomain)
	}
	state.mu.Unlock()

	log.Printf("client disconnected: %s", sshConn.RemoteAddr())
}

func handleChannels(chans <-chan ssh.NewChannel) {
	for newChan := range chans {
		newChan.Reject(ssh.UnknownChannelType, "unsupported channel type")
	}
}

func handleGlobalRequests(reqs <-chan *ssh.Request, sshConn *ssh.ServerConn, state *forwardState, reg *router) {
	for req := range reqs {
		switch req.Type {
		case "tcpip-forward":
			handleTCPIPForward(req, sshConn, state, reg)
		case "cancel-tcpip-forward":
			handleCancelTCPIPForward(req, state)
		case "gittunnel-subdomain":
			handleSubdomainRequest(req, state, reg, sshConn)
		default:
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}
}

func handleSubdomainRequest(req *ssh.Request, state *forwardState, reg *router, sshConn *ssh.ServerConn) {
	var payload subdomainRequestPayload
	if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
		req.Reply(false, nil)
		return
	}

	wanted := payload.Subdomain
	candidate := wanted
	if candidate == "" {
		candidate = randomSubdomain()
	}

	for attempts := 0; attempts < 5; attempts++ {
		if reg.reserve(candidate, sshConn) {
			state.mu.Lock()
			state.pendingSubdomain = candidate
			state.mu.Unlock()
			reply := subdomainReplyPayload{Subdomain: candidate}
			req.Reply(true, ssh.Marshal(&reply))
			return
		}
		if wanted != "" {
			req.Reply(false, nil)
			return
		}
		candidate = randomSubdomain()
	}

	req.Reply(false, nil)
}

func handleTCPIPForward(req *ssh.Request, sshConn *ssh.ServerConn, state *forwardState, reg *router) {
	var payload tcpIPForwardPayload
	if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
		req.Reply(false, nil)
		return
	}

	state.mu.Lock()
	subdomain := state.pendingSubdomain
	state.pendingSubdomain = ""
	state.mu.Unlock()

	if subdomain != "" {
		port := randomPort()
		reg.confirm(subdomain, payload.Addr, port)

		state.mu.Lock()
		state.subdomains[subdomain] = true
		state.mu.Unlock()

		reply := tcpIPForwardPayloadReply{Port: port}
		req.Reply(true, ssh.Marshal(&reply))
		log.Printf("tunnel opened: subdomain %s -> client %s", subdomain, sshConn.RemoteAddr())
		return
	}

	bindAddr := payload.Addr
	if bindAddr == "" || bindAddr == "localhost" {
		bindAddr = "0.0.0.0"
	}

	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", bindAddr, payload.Port))
	if err != nil {
		log.Printf("failed to bind %s:%d: %v", bindAddr, payload.Port, err)
		req.Reply(false, nil)
		return
	}

	actualPort := uint32(listener.Addr().(*net.TCPAddr).Port)
	key := fmt.Sprintf("%s:%d", bindAddr, actualPort)

	state.mu.Lock()
	state.listeners[key] = listener
	state.mu.Unlock()

	reply := tcpIPForwardPayloadReply{Port: actualPort}
	req.Reply(true, ssh.Marshal(&reply))

	log.Printf("tunnel opened: public %s -> client %s", listener.Addr().String(), sshConn.RemoteAddr())

	go acceptForwardedConns(listener, bindAddr, actualPort, sshConn)
}

func handleCancelTCPIPForward(req *ssh.Request, state *forwardState) {
	var payload tcpIPForwardPayload
	if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
		req.Reply(false, nil)
		return
	}
	key := fmt.Sprintf("%s:%d", payload.Addr, payload.Port)
	state.mu.Lock()
	if l, ok := state.listeners[key]; ok {
		l.Close()
		delete(state.listeners, key)
	}
	state.mu.Unlock()
	req.Reply(true, nil)
}

func acceptForwardedConns(listener net.Listener, bindAddr string, bindPort uint32, sshConn *ssh.ServerConn) {
	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			return
		}
		go forwardRawConn(tcpConn, bindAddr, bindPort, sshConn)
	}
}

func forwardRawConn(tcpConn net.Conn, bindAddr string, bindPort uint32, sshConn *ssh.ServerConn) {
	defer tcpConn.Close()

	originHost, originPortStr, err := net.SplitHostPort(tcpConn.RemoteAddr().String())
	if err != nil {
		return
	}
	var originPort uint32
	fmt.Sscanf(originPortStr, "%d", &originPort)

	payload := forwardedTCPPayload{
		Addr:       bindAddr,
		Port:       bindPort,
		OriginAddr: originHost,
		OriginPort: originPort,
	}

	channel, requests, err := sshConn.OpenChannel("forwarded-tcpip", ssh.Marshal(&payload))
	if err != nil {
		return
	}
	defer channel.Close()

	go ssh.DiscardRequests(requests)

	pipeConn(tcpConn, channel)
}

func runHTTPRouter(listenAddr, baseDomain string, reg *router) {
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("failed to start http router on %s: %v", listenAddr, err)
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("http router accept error: %v", err)
			continue
		}
		go handleHTTPConn(conn, baseDomain, reg)
	}
}

func handleHTTPConn(conn net.Conn, baseDomain string, reg *router) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	headerBytes, host, err := readHTTPHeaders(reader)
	if err != nil {
		return
	}

	subdomain := extractSubdomain(host, baseDomain)
	if subdomain == "" {
		writeHTTPError(conn, 400, "Bad Request")
		return
	}

	entry, ok := reg.lookup(subdomain)
	if !ok {
		writeHTTPError(conn, 404, "Not Found")
		return
	}

	originHost, originPortStr, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return
	}
	var originPort uint32
	fmt.Sscanf(originPortStr, "%d", &originPort)

	payload := forwardedTCPPayload{
		Addr:       entry.addr,
		Port:       entry.port,
		OriginAddr: originHost,
		OriginPort: originPort,
	}

	channel, requests, err := entry.sshConn.OpenChannel("forwarded-tcpip", ssh.Marshal(&payload))
	if err != nil {
		writeHTTPError(conn, 502, "Bad Gateway")
		return
	}
	defer channel.Close()

	go ssh.DiscardRequests(requests)

	channel.Write(headerBytes)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(channel, reader)
		channel.CloseWrite()
	}()
	go func() {
		defer wg.Done()
		io.Copy(conn, channel)
	}()
	wg.Wait()
}

func readHTTPHeaders(reader *bufio.Reader) ([]byte, string, error) {
	var buf bytes.Buffer
	host := ""
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, "", err
		}
		buf.WriteString(line)
		trimmed := strings.TrimRight(line, "\r\n")
		if trimmed == "" {
			break
		}
		lower := strings.ToLower(trimmed)
		if strings.HasPrefix(lower, "host:") {
			host = strings.TrimSpace(trimmed[len("host:"):])
		}
	}
	return buf.Bytes(), host, nil
}

func extractSubdomain(host, baseDomain string) string {
	h := host
	if idx := strings.Index(h, ":"); idx != -1 {
		h = h[:idx]
	}
	suffix := "." + baseDomain
	if !strings.HasSuffix(h, suffix) {
		return ""
	}
	return strings.TrimSuffix(h, suffix)
}

func writeHTTPError(conn net.Conn, code int, status string) {
	body := fmt.Sprintf("%d %s", code, status)
	response := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", code, status, len(body), body)
	conn.Write([]byte(response))
}

func pipeConn(a net.Conn, b ssh.Channel) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(b, a)
		b.CloseWrite()
	}()
	go func() {
		defer wg.Done()
		io.Copy(a, b)
	}()
	wg.Wait()
}
