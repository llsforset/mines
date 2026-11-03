package web

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/server/assets"
	"github.com/bishopfox/sliver/server/db"
)

type generateBody struct {
	Name      string `json:"name"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	C2        string `json:"c2"`
	Beacon    bool   `json:"beacon"`
	Interval  int64  `json:"interval"`
	Jitter    int64  `json:"jitter"`
	Format    string `json:"format"`
	Obfuscate bool   `json:"obfuscate"`
	Debug     bool   `json:"debug"`
	Reconnect int64  `json:"reconnect"`
}

func (s *Service) generate(w http.ResponseWriter, r *http.Request) {
	var body generateBody
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "生成参数不合法")
		return
	}
	if body.OS == "" || body.Arch == "" || body.C2 == "" {
		writeErr(w, http.StatusBadRequest, "要填写系统、芯片和回连地址")
		return
	}
	format := clientpb.OutputFormat_EXECUTABLE
	switch body.Format {
	case "", "EXECUTABLE":
		format = clientpb.OutputFormat_EXECUTABLE
	case "SHARED_LIB":
		format = clientpb.OutputFormat_SHARED_LIB
	case "SHELLCODE":
		format = clientpb.OutputFormat_SHELLCODE
	case "SERVICE":
		format = clientpb.OutputFormat_SERVICE
	default:
		writeErr(w, http.StatusBadRequest, "不支持的输出格式")
		return
	}
	interval := body.Interval
	if interval <= 0 {
		interval = 60
	}
	jitter := body.Jitter
	if jitter < 0 {
		jitter = 0
	}
	reconnect := body.Reconnect
	if reconnect <= 0 {
		reconnect = 60
	}
	cfg := &clientpb.ImplantConfig{
		GOOS:              body.OS,
		GOARCH:            body.Arch,
		IsBeacon:          body.Beacon,
		BeaconInterval:    int64(time.Duration(interval) * time.Second),
		BeaconJitter:      int64(time.Duration(jitter) * time.Second),
		ReconnectInterval: int64(time.Duration(reconnect) * time.Second),
		Debug:             body.Debug,
		ObfuscateSymbols:  body.Obfuscate,
		Format:            format,
		HTTPC2ConfigName:  "default",
		C2:                []*clientpb.ImplantC2{{URL: body.C2, Priority: 0}},
	}
	if err := s.replaceExistingBuild(r, body.Name, body.OS, body.Arch); err != nil {
		rpcErr(w, err)
		return
	}
	ctx := r.Context()
	resp, err := s.rpc.Generate(ctx, &clientpb.GenerateReq{Name: body.Name, Config: cfg})
	if err != nil {
		rpcErr(w, err)
		return
	}
	name := "implant"
	var data []byte
	if resp.GetFile() != nil {
		if resp.File.Name != "" {
			name = resp.File.Name
		}
		data = resp.File.Data
	}
	if resp.ImplantName != "" {
		w.Header().Set("X-Implant-Name", sanitizeName(resp.ImplantName))
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+sanitizeName(name)+"\"")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (s *Service) regenerate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	if err := decodeJSON(r, &body); err != nil || body.Name == "" {
		writeErr(w, http.StatusBadRequest, "缺少构建名称")
		return
	}
	resp, err := s.rpc.Regenerate(r.Context(), &clientpb.RegenerateReq{ImplantName: body.Name})
	if err != nil {
		rpcErr(w, err)
		return
	}
	name := body.Name
	var data []byte
	if resp.GetFile() != nil {
		if resp.File.Name != "" {
			name = resp.File.Name
		}
		data = resp.File.Data
	}
	w.Header().Set("X-Implant-Name", sanitizeName(resp.GetImplantName()))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+sanitizeName(name)+"\"")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (s *Service) replaceExistingBuild(r *http.Request, name, goos, goarch string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil
	}
	existing, err := db.ImplantBuildByName(name)
	if err != nil || existing == nil {
		removeBuildWorkspace(goos, goarch, name)
		return nil
	}
	return s.removeStoredBuild(r, name)
}

func (s *Service) removeStoredBuild(r *http.Request, name string) error {
	name = strings.TrimSpace(name)
	build, err := db.ImplantBuildByName(name)
	var id, goos, goarch string
	if err == nil && build != nil {
		id = build.ID
		if cfg, cfgErr := db.ImplantConfigByID(build.ImplantConfigID); cfgErr == nil && cfg != nil {
			goos = cfg.GOOS
			goarch = cfg.GOARCH
		}
	}
	if _, err = s.rpc.DeleteImplantBuild(r.Context(), &clientpb.DeleteReq{Name: name}); err != nil {
		return err
	}
	if id != "" {
		_ = os.Remove(filepath.Join(assets.GetRootAppDir(), "builds", id))
	}
	removeBuildWorkspace(goos, goarch, name)
	return nil
}

func removeBuildWorkspace(goos, goarch, name string) {
	if name == "" || strings.Contains(name, "/") || strings.Contains(name, "..") {
		return
	}
	if goos == "" || goarch == "" || strings.Contains(goos, "/") || strings.Contains(goarch, "/") {
		return
	}
	_ = os.RemoveAll(filepath.Join(assets.GetRootAppDir(), "slivers", goos, goarch, name))
}
