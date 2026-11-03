package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCommandCatalogMatchesClient(t *testing.T) {
	svc := NewService("test-token")
	server := httptest.NewServer(svc.Handler())
	defer server.Close()

	for _, menu := range []string{"server", "implant"} {
		req, err := http.NewRequest(http.MethodGet, server.URL+"/api/commands?menu="+menu, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer test-token")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("%s catalog status %d", menu, res.StatusCode)
		}
		var body struct {
			Commands []commandSpec `json:"commands"`
		}
		if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if len(body.Commands) < 20 {
			t.Fatalf("%s catalog too small: %d", menu, len(body.Commands))
		}
		ids := map[string]bool{}
		for _, spec := range body.Commands {
			ids[spec.ID] = true
			if spec.ID == "" || len(spec.Path) == 0 {
				t.Fatalf("empty command path: %#v", spec)
			}
		}
		if menu == "server" {
			for _, id := range []string{"generate", "jobs", "mtls", "https", "beacons", "sessions", "websites", "crack", "armory"} {
				if !ids[id] {
					t.Fatalf("server catalog missing %s", id)
				}
			}
		}
		if menu == "implant" {
			for _, id := range []string{"execute", "shell", "ls", "socks5", "portfwd", "screenshot", "execute-assembly", "migrate", "rportfwd"} {
				if !ids[id] && !hasPrefix(ids, id+" ") {
					t.Fatalf("implant catalog missing %s", id)
				}
			}
		}
	}
}

func TestShellCommandStaysOnTerminalPage(t *testing.T) {
	svc := NewService("test-token")
	server := httptest.NewServer(svc.Handler())
	defer server.Close()
	res := postJSON(t, server.URL+"/api/exec", `{"menu":"implant","sessionID":"missing","args":["shell"]}`, "test-token")
	defer res.Body.Close()
	var body map[string]string
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body["error"], "终端") {
		t.Fatalf("shell exec error = %q", body["error"])
	}
}

func hasPrefix(ids map[string]bool, prefix string) bool {
	for id := range ids {
		if strings.HasPrefix(id, prefix) || id == strings.TrimSpace(prefix) {
			return true
		}
	}
	return false
}
