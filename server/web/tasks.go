package web

import (
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
	"google.golang.org/protobuf/proto"
)

type taskRequest struct {
	Kind      string `json:"kind"`
	ID        string `json:"id"`
	Action    string `json:"action"`
	Path      string `json:"path"`
	Src       string `json:"src"`
	Dst       string `json:"dst"`
	Args      string `json:"args"`
	Name      string `json:"name"`
	Mode      string `json:"mode"`
	Pattern   string `json:"pattern"`
	Pid       int32  `json:"pid"`
	Force     bool   `json:"force"`
	Recursive bool   `json:"recursive"`
	Full      bool   `json:"full"`
	Output    bool   `json:"output"`
	TCP       bool   `json:"tcp"`
	UDP       bool   `json:"udp"`
	Listening bool   `json:"listening"`
	Hive      string `json:"hive"`
	Key       string `json:"key"`
	Hostname  string `json:"hostname"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	Domain    string `json:"domain"`
	Command   string `json:"command"`
	Port      uint32 `json:"port"`
	Reconnect int64  `json:"reconnect"`
	Interval  int64  `json:"interval"`
	Jitter    int64  `json:"jitter"`
	Timeout   int64  `json:"timeout"`
	Process   string `json:"process"`
}

func (t taskRequest) request() *commonpb.Request {
	seconds := t.Timeout
	if seconds <= 0 {
		seconds = 60
	}
	req := &commonpb.Request{Timeout: int64(time.Duration(seconds) * time.Second)}
	if t.Kind == "beacon" {
		req.Async = true
		req.BeaconID = t.ID
		return req
	}
	req.SessionID = t.ID
	return req
}

func (s *Service) task(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "只接受 POST")
		return
	}
	var body taskRequest
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "任务参数不合法")
		return
	}
	if body.ID == "" || (body.Kind != "session" && body.Kind != "beacon") {
		writeErr(w, http.StatusBadRequest, "需要指定 session 或 beacon")
		return
	}
	msg, err := s.dispatch(r, body)
	if err != nil {
		rpcErr(w, err)
		return
	}
	if msg == nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "action": body.Action})
		return
	}
	// Go 目标的下载在返回给浏览器的同时落一份到留档目录，前端可以再预览。
	if body.Action == "download" {
		if dl, ok := msg.(*sliverpb.Download); ok && len(dl.Data) > 0 {
			if rec, err := grabbedFiles.Save(body.Kind+":"+body.ID, dl.Path, dl.Data); err == nil {
				audit.Append(AuditEntry{
					At: time.Now(), Target: body.Kind + ":" + body.ID, Op: "download",
					Path: dl.Path, Size: int64(len(dl.Data)),
				})
				writeJSON(w, http.StatusOK, map[string]any{
					"Path":    dl.Path,
					"Exists":  dl.Exists,
					"Data":    dl.Data,
					"IsDir":   dl.IsDir,
					"Grabbed": rec,
				})
				return
			}
		}
	}
	if body.Action == "rm" || body.Action == "mv" || body.Action == "mkdir" {
		audit.Append(AuditEntry{
			At: time.Now(), Target: body.Kind + ":" + body.ID, Op: body.Action,
			Path: body.Path, Dst: body.Dst, Msg: "已下发",
		})
	}
	writeProto(w, msg)
}

func (s *Service) dispatch(r *http.Request, body taskRequest) (proto.Message, error) {
	ctx := r.Context()
	req := body.request()
	switch body.Action {
	case "ping":
		return s.rpc.Ping(ctx, &sliverpb.Ping{Request: req})
	case "pwd":
		return s.rpc.Pwd(ctx, &sliverpb.PwdReq{Request: req})
	case "ifconfig":
		return s.rpc.Ifconfig(ctx, &sliverpb.IfconfigReq{Request: req})
	case "netstat":
		return s.rpc.Netstat(ctx, &sliverpb.NetstatReq{TCP: body.TCP, UDP: body.UDP, Listening: body.Listening, Request: req})
	case "ps":
		return s.rpc.Ps(ctx, &sliverpb.PsReq{FullInfo: body.Full, Request: req})
	case "env":
		return s.rpc.GetEnv(ctx, &sliverpb.EnvReq{Name: body.Name, Request: req})
	case "setenv":
		return s.rpc.SetEnv(ctx, &sliverpb.SetEnvReq{Variable: &commonpb.EnvVar{Key: body.Name, Value: body.Args}, Request: req})
	case "unsetenv":
		return s.rpc.UnsetEnv(ctx, &sliverpb.UnsetEnvReq{Name: body.Name, Request: req})
	case "privs":
		return s.rpc.GetPrivs(ctx, &sliverpb.GetPrivsReq{Request: req})
	case "services":
		return s.rpc.Services(ctx, &sliverpb.ServicesReq{Hostname: body.Hostname, Request: req})
	case "mount":
		return s.rpc.Mount(ctx, &sliverpb.MountReq{Request: req})
	case "screenshot":
		return s.rpc.Screenshot(ctx, &sliverpb.ScreenshotReq{Request: req})
	case "ls":
		return s.rpc.Ls(ctx, &sliverpb.LsReq{Path: body.Path, Request: req})
	case "cd":
		return s.rpc.Cd(ctx, &sliverpb.CdReq{Path: body.Path, Request: req})
	case "mkdir":
		return s.rpc.Mkdir(ctx, &sliverpb.MkdirReq{Path: body.Path, Request: req})
	case "rm":
		return s.rpc.Rm(ctx, &sliverpb.RmReq{Path: body.Path, Recursive: body.Recursive, Force: body.Force, Request: req})
	case "mv":
		return s.rpc.Mv(ctx, &sliverpb.MvReq{Src: body.Src, Dst: body.Dst, Request: req})
	case "cp":
		return s.rpc.Cp(ctx, &sliverpb.CpReq{Src: body.Src, Dst: body.Dst, Request: req})
	case "chmod":
		return s.rpc.Chmod(ctx, &sliverpb.ChmodReq{Path: body.Path, FileMode: body.Mode, Recursive: body.Recursive, Request: req})
	case "download":
		return s.rpc.Download(ctx, &sliverpb.DownloadReq{Path: body.Path, RestrictedToFile: true, Request: req})
	case "grep":
		return s.rpc.Grep(ctx, &sliverpb.GrepReq{SearchPattern: body.Pattern, Path: body.Path, Recursive: body.Recursive, Request: req})
	case "execute":
		return s.rpc.Execute(ctx, &sliverpb.ExecuteReq{
			Path:    body.Path,
			Args:    splitArgs(body.Args),
			Output:  true,
			Request: req,
		})
	case "terminate":
		return s.rpc.Terminate(ctx, &sliverpb.TerminateReq{Pid: body.Pid, Force: body.Force, Request: req})
	case "procdump":
		return s.rpc.ProcessDump(ctx, &sliverpb.ProcessDumpReq{Pid: body.Pid, Request: req})
	case "reg-read":
		return s.rpc.RegistryRead(ctx, &sliverpb.RegistryReadReq{Hive: body.Hive, Path: body.Path, Key: body.Key, Hostname: body.Hostname, Request: req})
	case "reg-subkeys":
		return s.rpc.RegistryListSubKeys(ctx, &sliverpb.RegistrySubKeyListReq{Hive: body.Hive, Path: body.Path, Hostname: body.Hostname, Request: req})
	case "reg-values":
		return s.rpc.RegistryListValues(ctx, &sliverpb.RegistryListValuesReq{Hive: body.Hive, Path: body.Path, Hostname: body.Hostname, Request: req})
	case "runas":
		return s.rpc.RunAs(ctx, &sliverpb.RunAsReq{Username: body.Username, ProcessName: body.Process, Args: body.Args, Domain: body.Domain, Password: body.Password, Request: req})
	case "impersonate":
		return s.rpc.Impersonate(ctx, &sliverpb.ImpersonateReq{Username: body.Username, Request: req})
	case "rev2self":
		return s.rpc.RevToSelf(ctx, &sliverpb.RevToSelfReq{Request: req})
	case "make-token":
		return s.rpc.MakeToken(ctx, &sliverpb.MakeTokenReq{Username: body.Username, Password: body.Password, Domain: body.Domain, Request: req})
	case "token":
		return s.rpc.CurrentTokenOwner(ctx, &sliverpb.CurrentTokenOwnerReq{Request: req})
	case "ssh":
		return s.rpc.RunSSHCommand(ctx, &sliverpb.SSHCommandReq{Username: body.Username, Password: body.Password, Hostname: body.Hostname, Port: body.Port, Command: body.Command, Request: req})
	case "extensions":
		return s.rpc.ListExtensions(ctx, &sliverpb.ListExtensionsReq{Request: req})
	case "open-session":
		return s.rpc.OpenSession(ctx, &sliverpb.OpenSession{Request: req})
	case "close-session":
		return s.rpc.CloseSession(ctx, &sliverpb.CloseSession{Request: req})
	case "rename":
		rename := &clientpb.RenameReq{Name: body.Name}
		if body.Kind == "beacon" {
			rename.BeaconID = body.ID
		} else {
			rename.SessionID = body.ID
		}
		if _, err := s.rpc.Rename(ctx, rename); err != nil {
			return nil, err
		}
		return nil, nil
	case "reconfigure":
		reconf := &sliverpb.ReconfigureReq{Request: req}
		if body.Reconnect > 0 {
			reconf.ReconnectInterval = int64(time.Duration(body.Reconnect) * time.Second)
		}
		if body.Interval > 0 {
			reconf.BeaconInterval = int64(time.Duration(body.Interval) * time.Second)
		}
		if body.Jitter > 0 {
			reconf.BeaconJitter = int64(time.Duration(body.Jitter) * time.Second)
		}
		return s.rpc.Reconfigure(ctx, reconf)
	case "kill":
		if _, err := s.rpc.Kill(ctx, &sliverpb.KillReq{Force: body.Force, Request: req}); err != nil {
			return nil, err
		}
		return nil, nil
	case "remove":
		if body.Kind != "beacon" {
			return nil, errString("只有 beacon 可以从列表移除，session 请使用结束")
		}
		if _, err := s.rpc.RmBeacon(ctx, &clientpb.Beacon{ID: body.ID}); err != nil {
			return nil, err
		}
		return nil, nil
	default:
		return nil, errString("未知操作: " + body.Action)
	}
}

func (s *Service) upload(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(64 << 20); err != nil {
		writeErr(w, http.StatusBadRequest, "上传内容无法解析")
		return
	}
	body := taskRequest{
		Kind:   r.FormValue("kind"),
		ID:     r.FormValue("id"),
		Path:   r.FormValue("path"),
		Action: "upload",
	}
	if timeout := r.FormValue("timeout"); timeout != "" {
		if n, err := strconv.ParseInt(timeout, 10, 64); err == nil {
			body.Timeout = n
		}
	}
	if body.ID == "" || (body.Kind != "session" && body.Kind != "beacon") || body.Path == "" {
		writeErr(w, http.StatusBadRequest, "上传需要目标、类型和远程路径")
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "缺少文件")
		return
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 64<<20))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "读取上传文件失败")
		return
	}
	resp, err := s.rpc.Upload(r.Context(), &sliverpb.UploadReq{
		Path:     body.Path,
		Data:     data,
		FileName: header.Filename,
		Request:  body.request(),
	})
	if err != nil {
		rpcErr(w, err)
		return
	}
	audit.Append(AuditEntry{
		At: time.Now(), Target: body.Kind + ":" + body.ID, Op: "upload",
		Path: body.Path, Size: int64(len(data)), Msg: "已下发",
	})
	writeProto(w, resp)
}

func splitArgs(raw string) []string {
	return strings.Fields(raw)
}

type errString string

func (e errString) Error() string { return string(e) }
