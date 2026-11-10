package web

import (
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/bishopfox/sliver/server/assets"
	"github.com/bishopfox/sliver/server/litebeacon"
	"github.com/bishopfox/sliver/server/log"
	"github.com/bishopfox/sliver/server/rpc"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

//go:embed static/*
var staticFS embed.FS

// C 下载完成后由 litebeacon 回调进来，统一落到留档目录。
func init() {
	litebeacon.OnCompletedFile = func(beaconID string, taskID uint32, path string, data []byte) {
		if _, err := grabbedFiles.Save("lite:"+beaconID, path, data); err != nil {
			filesLog.Errorf("archive downloaded file: %s", err)
			return
		}
		audit.Append(AuditEntry{
			At: time.Now(), Target: "lite:" + beaconID, Op: "download",
			Path: path, Size: int64(len(data)),
		})
	}
	// 文件写回/删除/改名/建目录：完成即记录，谁在什么时候动了什么。
	litebeacon.OnFsResult = func(beaconID, op, path, dst string, errCode uint8, msg string) {
		audit.Append(AuditEntry{
			At: time.Now(), Target: "lite:" + beaconID, Op: op,
			Path: path, Dst: dst, Err: errCode, Msg: msg,
		})
	}
}

var (
	webLog    = log.NamedLogger("web", "console")
	startOnce sync.Once
	startErr  error

	protoMarshal = protojson.MarshalOptions{
		UseProtoNames:   true,
		EmitUnpopulated: false,
	}
)

const (
	defaultAddr = "127.0.0.1:9443"
	cookieName  = "sliver_web"
	webUser     = "admina"
	webPassword = "Admin0701@"
)

// Service is the local web console.
type Service struct {
	token      string
	rpc        *rpc.Server
	bridgeOnce sync.Once
	bridge     *bridge
	bridgeErr  error
	aliasOnce  sync.Once
	alias      *aliasBook
}

// Start listens for the web console. It is safe to call more than once.
// Set SLIVER_WEB=0 to skip it. SLIVER_WEB_ADDR overrides the listen address.
func Start() error {
	startOnce.Do(func() {
		if os.Getenv("SLIVER_WEB") == "0" {
			return
		}
		addr := os.Getenv("SLIVER_WEB_ADDR")
		if addr == "" {
			addr = defaultAddr
		}
		token, err := loadOrCreateToken()
		if err != nil {
			startErr = err
			return
		}
		svc := &Service{token: token, rpc: &rpc.Server{}}
		go func() {
			if _, err := litebeacon.EnsureZig(); err != nil {
				fmt.Printf("[!] Zig: %s\n", err)
				webLog.Errorf("Zig toolchain: %s", err)
			}
		}()
		server := &http.Server{
			Addr:              addr,
			Handler:           svc.Handler(),
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       2 * time.Minute,
		}
		lnErr := make(chan error, 1)
		go func() {
			webLog.Infof("Web console listening on http://%s", addr)
			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				lnErr <- err
			}
		}()
		select {
		case err := <-lnErr:
			startErr = err
		case <-time.After(200 * time.Millisecond):
			fmt.Printf("\n[*] Web console: http://%s\n", addr)
			fmt.Printf("[*] Web login:   %s\n\n", webUser)
		}
	})
	return startErr
}

// NewService builds a console service with an explicit token. Tests use this.
func NewService(token string) *Service {
	return &Service{token: token, rpc: &rpc.Server{}}
}

// Handler is the HTTP handler for the console and its API.
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/login", s.login)
	mux.HandleFunc("/api/version", s.auth(s.version))
	mux.HandleFunc("/api/overview", s.auth(s.overview))
	mux.HandleFunc("/api/sessions", s.auth(s.sessions))
	mux.HandleFunc("/api/beacons", s.auth(s.beacons))
	mux.HandleFunc("/api/beacons/tasks", s.auth(s.beaconTasks))
	mux.HandleFunc("/api/jobs", s.auth(s.jobs))
	mux.HandleFunc("/api/listeners/mtls", s.auth(s.startMTLS))
	mux.HandleFunc("/api/listeners/http", s.auth(s.startHTTP))
	mux.HandleFunc("/api/listeners/https", s.auth(s.startHTTPS))
	mux.HandleFunc("/api/listeners/dns", s.auth(s.startDNS))
	mux.HandleFunc("/api/jobs/kill", s.auth(s.killJob))
	mux.HandleFunc("/api/implants/builds", s.auth(s.builds))
	mux.HandleFunc("/api/implants/profiles", s.auth(s.profiles))
	mux.HandleFunc("/api/implants/generate", s.auth(s.generate))
	mux.HandleFunc("/api/implants/generate-c", s.auth(s.generateC))
	mux.HandleFunc("/api/implants/regenerate", s.auth(s.regenerate))
	mux.HandleFunc("/api/implants/builds/delete", s.auth(s.deleteBuild))
	mux.HandleFunc("/api/loot", s.auth(s.loot))
	mux.HandleFunc("/api/loot/delete", s.auth(s.lootDelete))
	mux.HandleFunc("/api/loot/content", s.auth(s.lootContent))
	mux.HandleFunc("/api/creds", s.auth(s.creds))
	mux.HandleFunc("/api/creds/add", s.auth(s.credsAdd))
	mux.HandleFunc("/api/creds/delete", s.auth(s.credsDelete))
	mux.HandleFunc("/api/hosts", s.auth(s.hosts))
	mux.HandleFunc("/api/hosts/delete", s.auth(s.hostDelete))
	mux.HandleFunc("/api/websites", s.auth(s.websites))
	mux.HandleFunc("/api/websites/delete", s.auth(s.websiteDelete))
	mux.HandleFunc("/api/websites/content", s.auth(s.websiteAddContent))
	mux.HandleFunc("/api/websites/content/delete", s.auth(s.websiteRemoveContent))
	mux.HandleFunc("/api/operators", s.auth(s.operators))
	mux.HandleFunc("/api/c2profiles", s.auth(s.c2profiles))
	mux.HandleFunc("/api/canaries", s.auth(s.canaries))
	mux.HandleFunc("/api/builders", s.auth(s.builders))
	mux.HandleFunc("/api/compiler", s.auth(s.compiler))
	mux.HandleFunc("/api/pivots", s.auth(s.pivots))
	mux.HandleFunc("/api/certificates", s.auth(s.certificates))
	mux.HandleFunc("/api/task", s.auth(s.task))
	mux.HandleFunc("/api/lite/listener/start", s.auth(s.liteListenerStart))
	mux.HandleFunc("/api/lite/listener/stop", s.auth(s.liteListenerStop))
	mux.HandleFunc("/api/lite/config", s.auth(s.liteConfig))
	mux.HandleFunc("/api/lite/beacons", s.auth(s.liteBeacons))
	mux.HandleFunc("/api/lite/beacon/delete", s.auth(s.liteBeaconDelete))
	mux.HandleFunc("/api/targets/aliases", s.auth(s.targetAliases))
	mux.HandleFunc("/api/targets/rename", s.auth(s.targetRename))
	mux.HandleFunc("/api/targets/remove", s.auth(s.targetRemove))
	mux.HandleFunc("/api/targets/stop", s.auth(s.targetStop))
	mux.HandleFunc("/api/lite/task", s.auth(s.liteTask))
	mux.HandleFunc("/api/lite/results", s.auth(s.liteResults))
	mux.HandleFunc("/api/lite/ls", s.auth(s.liteLs))
	mux.HandleFunc("/api/lite/fs", s.auth(s.liteFs))
	mux.HandleFunc("/api/files", s.auth(s.filesList))
	mux.HandleFunc("/api/files/raw", s.auth(s.filesRaw))
	mux.HandleFunc("/api/files/audit", s.auth(s.filesAudit))
	mux.HandleFunc("/api/upload", s.auth(s.upload))
	mux.HandleFunc("/api/commands", s.auth(s.commandCatalog))
	mux.HandleFunc("/api/exec", s.auth(s.exec))
	mux.HandleFunc("/api/shell", s.auth(s.shellSocket))
	mux.HandleFunc("/", s.static)
	return mux
}

func (s *Service) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !tokensEqual(tokenFrom(r), s.token) {
			writeErr(w, http.StatusUnauthorized, "还没登录，或账号密码不对")
			return
		}
		next(w, r)
	}
}

func tokenFrom(r *http.Request) string {
	if header := r.Header.Get("Authorization"); strings.HasPrefix(header, "Bearer ") {
		return strings.TrimPrefix(header, "Bearer ")
	}
	if cookie, err := r.Cookie(cookieName); err == nil {
		return cookie.Value
	}
	return r.URL.Query().Get("token")
}

func tokensEqual(got, want string) bool {
	if got == "" || want == "" || len(got) != len(want) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func (s *Service) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "只接受 POST")
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "请求不是合法 JSON")
		return
	}
	if !tokensEqual(strings.TrimSpace(body.Username), webUser) || !tokensEqual(body.Password, webPassword) {
		writeErr(w, http.StatusUnauthorized, "账号或密码不对")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    s.token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "token": s.token})
}

func (s *Service) static(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeErr(w, http.StatusMethodNotAllowed, "只接受 GET")
		return
	}
	name := r.URL.Path
	switch name {
	case "/", "":
		name = "static/index.html"
	case "/app.css":
		name = "static/app.css"
	case "/app.js":
		name = "static/app.js"
	case "/commands.js":
		name = "static/commands.js"
	default:
		http.NotFound(w, r)
		return
	}
	data, err := staticFS.ReadFile(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	switch {
	case strings.HasSuffix(name, ".css"):
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	case strings.HasSuffix(name, ".js"):
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	default:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(data)
	}
}

func tokenPath() string {
	return filepath.Join(assets.GetRootAppDir(), "web.token")
}

func loadOrCreateToken() (string, error) {
	path := tokenPath()
	if data, err := os.ReadFile(path); err == nil {
		token := strings.TrimSpace(string(data))
		if token != "" {
			return token, nil
		}
	}
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	token := hex.EncodeToString(buf)
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		return "", err
	}
	return token, nil
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"error": msg})
}

func writeJSON(w http.ResponseWriter, code int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(value)
}

func writeProto(w http.ResponseWriter, msg proto.Message) {
	data, err := protoMarshal.Marshal(msg)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func decodeJSON(r *http.Request, dest any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, 32<<20))
	return dec.Decode(dest)
}

func rpcErr(w http.ResponseWriter, err error) {
	writeErr(w, http.StatusBadGateway, err.Error())
}
