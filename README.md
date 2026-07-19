# GitTunnel

SSH-based reverse tunnel with subdomain HTTP routing. Exposes `localhost:PORT`
as `https://<subdomain>.<base-domain>` through a single public HTTP listener.

## Build

```
go mod tidy
go build -o bin/gittunnel-server ./cmd/server
go build -o bin/gittunnel-client ./cmd/client
```

## Server setup (public VPS)

1. Create `authorized_keys` in the working directory with the public keys of
   clients allowed to open tunnels (same format as `~/.ssh/authorized_keys`).
2. Point your base domain's DNS at the VPS with a wildcard record, e.g.
   `*.tunnels.example.com A <vps-ip>`.
3. Open the SSH control port (default `2222`) and the HTTP router port
   (default `8080`, or `80`/`443` behind a TLS terminator).
4. Run:

```
GITTUNNEL_LISTEN=0.0.0.0:2222 \
GITTUNNEL_HTTP_LISTEN=0.0.0.0:8080 \
GITTUNNEL_BASE_DOMAIN=tunnels.example.com \
./bin/gittunnel-server
```

## Client usage (local machine)

```
GITTUNNEL_SERVER=your.server.ip:2222 \
GITTUNNEL_LOCAL=127.0.0.1:3000 \
GITTUNNEL_USER=tunnel \
GITTUNNEL_KEY=$HOME/.ssh/id_rsa \
GITTUNNEL_BASE_DOMAIN=tunnels.example.com \
GITTUNNEL_SUBDOMAIN=myapp \
./bin/gittunnel-client
```

Leave `GITTUNNEL_SUBDOMAIN` unset to get a random subdomain assigned by the
server. On success the client logs the public URL, e.g.
`https://myapp.tunnels.example.com`.

## How the HTTP routing works

- The client sends a custom SSH global request (`gittunnel-subdomain`) to
  reserve a subdomain before opening its reverse tunnel.
- The server keeps an in-memory registry mapping `subdomain -> SSH connection`.
- The public HTTP listener (`GITTUNNEL_HTTP_LISTEN`) peeks at the `Host`
  header of each incoming request, looks up the owning SSH connection in the
  registry, and opens a `forwarded-tcpip` channel directly into that client —
  no per-tunnel public TCP port is bound.
- Raw, non-HTTP TCP forwarding is still supported by simply not calling the
  subdomain request first; the server falls back to binding a real public
  port per tunnel in that case.

## Notes / production hardening not yet included

- Client uses `ssh.InsecureIgnoreHostKey()` — pin the server's host key
  fingerprint before shipping this to real users.
- No TLS termination — put this behind a reverse proxy (Caddy/nginx) or add
  `crypto/tls` directly on the HTTP router listener for real HTTPS.
- No rate limiting, connection caps, or bandwidth quotas per tunnel.
- Host key is regenerated on every server restart; persist it to disk if you
  want a stable fingerprint.
- Subdomain reservations from a crashed handshake (subdomain requested but
  `tcpip-forward` never follows) are cleaned up only when the SSH connection
  itself closes.
