package web

import (
	"net/http"

	"github.com/bishopfox/sliver/server/litebeacon"
)

func (s *Service) generateC(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name    string `json:"name"`
		OS      string `json:"os"`
		Arch    string `json:"arch"`
		URL     string `json:"url"`
		Path    string `json:"path"`
		IdleSec int    `json:"idleSec"`
		FastSec int    `json:"fastSec"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "生成参数不合法")
		return
	}
	name, data, err := litebeacon.Build(litebeacon.BuildRequest{
		Name: body.Name, OS: body.OS, Arch: body.Arch,
		URL: body.URL, Path: body.Path, IdleSec: body.IdleSec, FastSec: body.FastSec,
	})
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	w.Header().Set("X-Implant-Name", sanitizeName(name))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+sanitizeName(name)+"\"")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}
