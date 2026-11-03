package web

import (
	"net/http"
)

func (s *Service) commandCatalog(w http.ResponseWriter, r *http.Request) {
	menu := r.URL.Query().Get("menu")
	if menu == "" {
		menu = "server"
	}
	if menu != "server" && menu != "implant" {
		writeErr(w, http.StatusBadRequest, "menu 只能是 server 或 implant")
		return
	}
	specs, err := s.commands(menu)
	if err != nil {
		rpcErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"menu": menu, "commands": specs})
}

func (s *Service) exec(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "只接受 POST")
		return
	}
	var body struct {
		Menu      string   `json:"menu"`
		SessionID string   `json:"sessionID"`
		BeaconID  string   `json:"beaconID"`
		Args      []string `json:"args"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "命令参数不合法")
		return
	}
	if body.Menu == "" {
		body.Menu = "server"
	}
	output, err := s.execCommand(body.Menu, body.SessionID, body.BeaconID, body.Args)
	resp := map[string]any{"output": output}
	if err != nil {
		resp["error"] = err.Error()
	}
	writeJSON(w, http.StatusOK, resp)
}
