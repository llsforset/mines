package web

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
	"github.com/bishopfox/sliver/server/assets"
	"github.com/bishopfox/sliver/server/core"
	"github.com/bishopfox/sliver/server/db"
	"github.com/bishopfox/sliver/server/litebeacon"
)

type targetBody struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
	Name string `json:"name"`
}

type aliasBook struct {
	mu    sync.Mutex
	path  string
	names map[string]string
}

func (s *Service) aliases() *aliasBook {
	s.aliasOnce.Do(func() {
		s.alias = loadAliasBook(filepath.Join(assets.GetRootAppDir(), "target-aliases.json"))
	})
	return s.alias
}

func loadAliasBook(path string) *aliasBook {
	book := &aliasBook{path: path, names: map[string]string{}}
	data, err := os.ReadFile(path)
	if err != nil {
		return book
	}
	if err := json.Unmarshal(data, &book.names); err != nil || book.names == nil {
		book.names = map[string]string{}
	}
	return book
}

func (b *aliasBook) snapshot() map[string]string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make(map[string]string, len(b.names))
	for id, name := range b.names {
		out[id] = name
	}
	return out
}

func (b *aliasBook) set(id, name string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.names == nil {
		b.names = map[string]string{}
	}
	b.names[id] = name
	return b.saveLocked()
}

func (b *aliasBook) delete(id string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.names[id]; !ok {
		return
	}
	delete(b.names, id)
	_ = b.saveLocked()
}

func (b *aliasBook) saveLocked() error {
	data, err := json.MarshalIndent(b.names, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(b.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp := b.path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, b.path)
}

func cleanAlias(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", errString("别名不能为空")
	}
	if utf8.RuneCountInString(name) > 32 {
		return "", errString("别名最多 32 个字")
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return "", errString("别名里不能有控制字符")
		}
	}
	return name, nil
}

func validTargetID(id string) bool {
	if id == "" || len(id) > 128 {
		return false
	}
	for _, r := range id {
		if r < 0x20 || r == 0x7f || r == ' ' {
			return false
		}
	}
	return true
}

func (s *Service) targetAliases(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "只接受 GET")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"aliases": s.aliases().snapshot()})
}

func (s *Service) targetRename(w http.ResponseWriter, r *http.Request) {
	body, ok := s.readTarget(w, r)
	if !ok {
		return
	}
	if err := s.ensureTarget(body.Kind, body.ID); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" {
		s.aliases().delete(body.ID)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "name": ""})
		return
	}
	name, err := cleanAlias(name)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.aliases().set(body.ID, name); err != nil {
		rpcErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "name": name})
}

func (s *Service) targetRemove(w http.ResponseWriter, r *http.Request) {
	body, ok := s.readTarget(w, r)
	if !ok {
		return
	}
	if err := s.ensureTarget(body.Kind, body.ID); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	var err error
	switch body.Kind {
	case "session":
		_, err = s.rpc.CloseSession(r.Context(), &sliverpb.CloseSession{
			Request: &commonpb.Request{SessionID: body.ID},
		})
	case "beacon":
		_, err = s.rpc.RmBeacon(r.Context(), &clientpb.Beacon{ID: body.ID})
	case "lite":
		litebeacon.DeleteBeacon(body.ID)
	}
	if err != nil {
		rpcErr(w, err)
		return
	}
	s.aliases().delete(body.ID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Service) targetStop(w http.ResponseWriter, r *http.Request) {
	body, ok := s.readTarget(w, r)
	if !ok {
		return
	}
	if err := s.ensureTarget(body.Kind, body.ID); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	switch body.Kind {
	case "lite":
		if _, queued := litebeacon.QueueTask(body.ID, litebeacon.Task{Type: litebeacon.TaskExit}); !queued {
			writeErr(w, http.StatusBadRequest, "这台机器已经不在列表里")
			return
		}
	case "session":
		_, err := s.rpc.Kill(r.Context(), &sliverpb.KillReq{
			Force:   true,
			Request: &commonpb.Request{SessionID: body.ID},
		})
		if err != nil {
			rpcErr(w, err)
			return
		}
	case "beacon":
		_, err := s.rpc.Kill(r.Context(), &sliverpb.KillReq{
			Force:   true,
			Request: &commonpb.Request{BeaconID: body.ID},
		})
		if err != nil {
			rpcErr(w, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Service) readTarget(w http.ResponseWriter, r *http.Request) (targetBody, bool) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "只接受 POST")
		return targetBody{}, false
	}
	var body targetBody
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "请求不是合法 JSON")
		return targetBody{}, false
	}
	body.Kind = strings.TrimSpace(body.Kind)
	body.ID = strings.TrimSpace(body.ID)
	if body.Kind != "session" && body.Kind != "beacon" && body.Kind != "lite" {
		writeErr(w, http.StatusBadRequest, "不知道这是哪种目标")
		return targetBody{}, false
	}
	if !validTargetID(body.ID) {
		writeErr(w, http.StatusBadRequest, "目标编号不对")
		return targetBody{}, false
	}
	return body, true
}

func (s *Service) ensureTarget(kind, id string) error {
	switch kind {
	case "session":
		if core.Sessions.Get(id) == nil {
			return errString("这台机器已经不在列表里")
		}
	case "beacon":
		beacon, err := db.BeaconByID(id)
		if err != nil || beacon == nil {
			return errString("这台机器已经不在列表里")
		}
	case "lite":
		for _, item := range litebeacon.ListBeacons() {
			if item.ID == id {
				return nil
			}
		}
		return errString("这台机器已经不在列表里")
	default:
		return errString("不知道这是哪种目标")
	}
	return nil
}
