package web

import (
	"io"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
)

func (s *Service) version(w http.ResponseWriter, r *http.Request) {
	ver, err := s.rpc.GetVersion(r.Context(), &commonpb.Empty{})
	if err != nil {
		rpcErr(w, err)
		return
	}
	writeProto(w, ver)
}

func (s *Service) overview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sessions, err := s.rpc.GetSessions(ctx, &commonpb.Empty{})
	if err != nil {
		rpcErr(w, err)
		return
	}
	beacons, err := s.rpc.GetBeacons(ctx, &commonpb.Empty{})
	if err != nil {
		rpcErr(w, err)
		return
	}
	jobs, err := s.rpc.GetJobs(ctx, &commonpb.Empty{})
	if err != nil {
		rpcErr(w, err)
		return
	}
	aliveSessions := 0
	for _, session := range sessions.GetSessions() {
		if session != nil && !session.IsDead {
			aliveSessions++
		}
	}
	aliveBeacons := 0
	for _, beacon := range beacons.GetBeacons() {
		if beacon != nil && !beacon.IsDead {
			aliveBeacons++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"sessions":      len(sessions.GetSessions()),
		"sessionsAlive": aliveSessions,
		"beacons":       len(beacons.GetBeacons()),
		"beaconsAlive":  aliveBeacons,
		"jobs":          len(jobs.GetActive()),
		"time":          time.Now().Unix(),
	})
}

func (s *Service) sessions(w http.ResponseWriter, r *http.Request) {
	resp, err := s.rpc.GetSessions(r.Context(), &commonpb.Empty{})
	if err != nil {
		rpcErr(w, err)
		return
	}
	writeProto(w, resp)
}

func (s *Service) beacons(w http.ResponseWriter, r *http.Request) {
	resp, err := s.rpc.GetBeacons(r.Context(), &commonpb.Empty{})
	if err != nil {
		rpcErr(w, err)
		return
	}
	writeProto(w, resp)
}

func (s *Service) beaconTasks(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		writeErr(w, http.StatusBadRequest, "缺少 beacon id")
		return
	}
	resp, err := s.rpc.GetBeaconTasks(r.Context(), &clientpb.Beacon{ID: id})
	if err != nil {
		rpcErr(w, err)
		return
	}
	for _, task := range resp.GetTasks() {
		if task == nil {
			continue
		}
		task.Request = nil
		task.Response = nil
	}
	writeProto(w, resp)
}

func (s *Service) jobs(w http.ResponseWriter, r *http.Request) {
	resp, err := s.rpc.GetJobs(r.Context(), &commonpb.Empty{})
	if err != nil {
		rpcErr(w, err)
		return
	}
	writeProto(w, resp)
}

type listenerReq struct {
	Host    string   `json:"host"`
	Port    uint32   `json:"port"`
	Domain  string   `json:"domain"`
	Domains []string `json:"domains"`
	Website string   `json:"website"`
}

func (s *Service) startMTLS(w http.ResponseWriter, r *http.Request) {
	var body listenerReq
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "监听端口的参数不对")
		return
	}
	resp, err := s.rpc.StartMTLSListener(r.Context(), &clientpb.MTLSListenerReq{Host: body.Host, Port: body.Port})
	if err != nil {
		rpcErr(w, err)
		return
	}
	writeProto(w, resp)
}

func (s *Service) startHTTP(w http.ResponseWriter, r *http.Request) {
	s.startHTTPListener(w, r, false)
}

func (s *Service) startHTTPS(w http.ResponseWriter, r *http.Request) {
	s.startHTTPListener(w, r, true)
}

func (s *Service) startHTTPListener(w http.ResponseWriter, r *http.Request, secure bool) {
	var body listenerReq
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "监听端口的参数不对")
		return
	}
	req := &clientpb.HTTPListenerReq{Host: body.Host, Port: body.Port, Domain: body.Domain, Secure: secure, Website: body.Website}
	var (
		resp *clientpb.ListenerJob
		err  error
	)
	if secure {
		resp, err = s.rpc.StartHTTPSListener(r.Context(), req)
	} else {
		resp, err = s.rpc.StartHTTPListener(r.Context(), req)
	}
	if err != nil {
		rpcErr(w, err)
		return
	}
	writeProto(w, resp)
}

func (s *Service) startDNS(w http.ResponseWriter, r *http.Request) {
	var body listenerReq
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "监听端口的参数不对")
		return
	}
	domains := body.Domains
	if body.Domain != "" {
		domains = append(domains, body.Domain)
	}
	resp, err := s.rpc.StartDNSListener(r.Context(), &clientpb.DNSListenerReq{
		Host:    body.Host,
		Port:    body.Port,
		Domains: domains,
	})
	if err != nil {
		rpcErr(w, err)
		return
	}
	writeProto(w, resp)
}

func (s *Service) killJob(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID uint32 `json:"id"`
	}
	if err := decodeJSON(r, &body); err != nil || body.ID == 0 {
		writeErr(w, http.StatusBadRequest, "缺少任务 ID")
		return
	}
	resp, err := s.rpc.KillJob(r.Context(), &clientpb.KillJobReq{ID: body.ID})
	if err != nil {
		rpcErr(w, err)
		return
	}
	writeProto(w, resp)
}

func (s *Service) builds(w http.ResponseWriter, r *http.Request) {
	resp, err := s.rpc.ImplantBuilds(r.Context(), &commonpb.Empty{})
	if err != nil {
		rpcErr(w, err)
		return
	}
	for _, cfg := range resp.GetConfigs() {
		if cfg == nil {
			continue
		}
		for _, build := range cfg.ImplantBuilds {
			if build == nil {
				continue
			}
			build.PeerPrivateKey = ""
			build.MtlsKey = ""
			build.WGImplantPrivKey = ""
		}
	}
	writeProto(w, resp)
}

func (s *Service) profiles(w http.ResponseWriter, r *http.Request) {
	resp, err := s.rpc.ImplantProfiles(r.Context(), &commonpb.Empty{})
	if err != nil {
		rpcErr(w, err)
		return
	}
	writeProto(w, resp)
}

func (s *Service) deleteBuild(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	if err := decodeJSON(r, &body); err != nil || body.Name == "" {
		writeErr(w, http.StatusBadRequest, "缺少构建名称")
		return
	}
	if err := s.removeStoredBuild(r, body.Name); err != nil {
		rpcErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Service) loot(w http.ResponseWriter, r *http.Request) {
	resp, err := s.rpc.LootAll(r.Context(), &commonpb.Empty{})
	if err != nil {
		rpcErr(w, err)
		return
	}
	for _, item := range resp.GetLoot() {
		if item != nil && item.File != nil {
			item.File.Data = nil
		}
	}
	writeProto(w, resp)
}

func (s *Service) lootDelete(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID string `json:"id"`
	}
	if err := decodeJSON(r, &body); err != nil || body.ID == "" {
		writeErr(w, http.StatusBadRequest, "缺少 loot id")
		return
	}
	if _, err := s.rpc.LootRm(r.Context(), &clientpb.Loot{ID: body.ID}); err != nil {
		rpcErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Service) lootContent(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		writeErr(w, http.StatusBadRequest, "缺少 loot id")
		return
	}
	resp, err := s.rpc.LootContent(r.Context(), &clientpb.Loot{ID: id})
	if err != nil {
		rpcErr(w, err)
		return
	}
	name := "loot.bin"
	var data []byte
	if resp.GetFile() != nil {
		if resp.File.Name != "" {
			name = resp.File.Name
		}
		data = resp.File.Data
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+sanitizeName(name)+"\"")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (s *Service) creds(w http.ResponseWriter, r *http.Request) {
	resp, err := s.rpc.Creds(r.Context(), &commonpb.Empty{})
	if err != nil {
		rpcErr(w, err)
		return
	}
	writeProto(w, resp)
}

func (s *Service) credsAdd(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username   string `json:"username"`
		Plaintext  string `json:"plaintext"`
		Hash       string `json:"hash"`
		Collection string `json:"collection"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "账号密码没填对")
		return
	}
	_, err := s.rpc.CredsAdd(r.Context(), &clientpb.Credentials{Credentials: []*clientpb.Credential{{
		Username:   body.Username,
		Plaintext:  body.Plaintext,
		Hash:       body.Hash,
		Collection: body.Collection,
	}}})
	if err != nil {
		rpcErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Service) credsDelete(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID string `json:"id"`
	}
	if err := decodeJSON(r, &body); err != nil || body.ID == "" {
		writeErr(w, http.StatusBadRequest, "没有指定要删除的账号")
		return
	}
	if _, err := s.rpc.CredsRm(r.Context(), &clientpb.Credentials{Credentials: []*clientpb.Credential{{ID: body.ID}}}); err != nil {
		rpcErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Service) hosts(w http.ResponseWriter, r *http.Request) {
	resp, err := s.rpc.Hosts(r.Context(), &commonpb.Empty{})
	if err != nil {
		rpcErr(w, err)
		return
	}
	writeProto(w, resp)
}

func (s *Service) hostDelete(w http.ResponseWriter, r *http.Request) {
	var body struct {
		HostUUID string `json:"hostUUID"`
	}
	if err := decodeJSON(r, &body); err != nil || body.HostUUID == "" {
		writeErr(w, http.StatusBadRequest, "缺少主机 UUID")
		return
	}
	if _, err := s.rpc.HostRm(r.Context(), &clientpb.Host{HostUUID: body.HostUUID}); err != nil {
		rpcErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Service) websites(w http.ResponseWriter, r *http.Request) {
	resp, err := s.rpc.Websites(r.Context(), &commonpb.Empty{})
	if err != nil {
		rpcErr(w, err)
		return
	}
	for _, site := range resp.GetWebsites() {
		for _, content := range site.GetContents() {
			if content != nil {
				content.Content = nil
			}
		}
	}
	writeProto(w, resp)
}

func (s *Service) websiteDelete(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	if err := decodeJSON(r, &body); err != nil || body.Name == "" {
		writeErr(w, http.StatusBadRequest, "缺少站点名称")
		return
	}
	if _, err := s.rpc.WebsiteRemove(r.Context(), &clientpb.Website{Name: body.Name}); err != nil {
		rpcErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Service) websiteAddContent(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeErr(w, http.StatusBadRequest, "上传内容无法解析")
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	webPath := normalizeWebPath(r.FormValue("path"))
	if name == "" || strings.Contains(name, "/") || strings.Contains(name, "..") {
		writeErr(w, http.StatusBadRequest, "要填写网站名称")
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "要选择一个文件")
		return
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 32<<20))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "读取文件失败")
		return
	}
	contentType := strings.TrimSpace(r.FormValue("contentType"))
	resp, err := s.rpc.WebsiteAddContent(r.Context(), &clientpb.WebsiteAddContent{
		Name: name,
		Contents: map[string]*clientpb.WebContent{
			webPath: {
				Path:           webPath,
				ContentType:    contentType,
				OriginalFile:   header.Filename,
				Content:        data,
				ReplaceContent: true,
			},
		},
	})
	if err != nil {
		rpcErr(w, err)
		return
	}
	for _, content := range resp.GetContents() {
		if content != nil {
			content.Content = nil
		}
	}
	writeProto(w, resp)
}

func (s *Service) websiteRemoveContent(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
		Path string `json:"path"`
	}
	if err := decodeJSON(r, &body); err != nil || body.Name == "" || body.Path == "" {
		writeErr(w, http.StatusBadRequest, "要指定网站名称和路径")
		return
	}
	resp, err := s.rpc.WebsiteRemoveContent(r.Context(), &clientpb.WebsiteRemoveContent{
		Name:  body.Name,
		Paths: []string{normalizeWebPath(body.Path)},
	})
	if err != nil {
		rpcErr(w, err)
		return
	}
	for _, content := range resp.GetContents() {
		if content != nil {
			content.Content = nil
		}
	}
	writeProto(w, resp)
}

func normalizeWebPath(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		value = "/"
	}
	if !strings.HasPrefix(value, "/") {
		value = "/" + value
	}
	cleaned := path.Clean(value)
	if cleaned == "." {
		return "/"
	}
	return cleaned
}

func (s *Service) operators(w http.ResponseWriter, r *http.Request) {
	resp, err := s.rpc.GetOperators(r.Context(), &commonpb.Empty{})
	if err != nil {
		rpcErr(w, err)
		return
	}
	writeProto(w, resp)
}

func (s *Service) c2profiles(w http.ResponseWriter, r *http.Request) {
	resp, err := s.rpc.GetHTTPC2Profiles(r.Context(), &commonpb.Empty{})
	if err != nil {
		rpcErr(w, err)
		return
	}
	writeProto(w, resp)
}

func (s *Service) canaries(w http.ResponseWriter, r *http.Request) {
	resp, err := s.rpc.Canaries(r.Context(), &commonpb.Empty{})
	if err != nil {
		rpcErr(w, err)
		return
	}
	writeProto(w, resp)
}

func (s *Service) builders(w http.ResponseWriter, r *http.Request) {
	resp, err := s.rpc.Builders(r.Context(), &commonpb.Empty{})
	if err != nil {
		rpcErr(w, err)
		return
	}
	writeProto(w, resp)
}

func (s *Service) compiler(w http.ResponseWriter, r *http.Request) {
	resp, err := s.rpc.GetCompiler(r.Context(), &commonpb.Empty{})
	if err != nil {
		rpcErr(w, err)
		return
	}
	writeProto(w, resp)
}

func (s *Service) pivots(w http.ResponseWriter, r *http.Request) {
	resp, err := s.rpc.PivotGraph(r.Context(), &commonpb.Empty{})
	if err != nil {
		rpcErr(w, err)
		return
	}
	writeProto(w, resp)
}

func (s *Service) certificates(w http.ResponseWriter, r *http.Request) {
	resp, err := s.rpc.GetCertificateAuthorityInfo(r.Context(), &commonpb.Empty{})
	if err != nil {
		rpcErr(w, err)
		return
	}
	writeProto(w, resp)
}

func sanitizeName(name string) string {
	out := make([]rune, 0, len(name))
	for _, r := range name {
		switch r {
		case '/', '\\', '"', '\n', '\r':
			out = append(out, '_')
		default:
			out = append(out, r)
		}
	}
	if len(out) == 0 {
		return "download.bin"
	}
	return string(out)
}
