package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestConsoleAuthAndStatic(t *testing.T) {
	svc := NewService("test-token")
	server := httptest.NewServer(svc.Handler())
	defer server.Close()

	index, err := http.Get(server.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer index.Body.Close()
	if index.StatusCode != http.StatusOK || !strings.Contains(index.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("index status %d type %s", index.StatusCode, index.Header.Get("Content-Type"))
	}

	denied, err := http.Get(server.URL + "/api/sessions")
	if err != nil {
		t.Fatal(err)
	}
	defer denied.Body.Close()
	if denied.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", denied.StatusCode)
	}

	bad := postJSON(t, server.URL+"/api/login", `{"username":"admina","password":"wrong"}`, "")
	if bad.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad login status %d", bad.StatusCode)
	}
	bad.Body.Close()

	good := postJSON(t, server.URL+"/api/login", `{"username":"admina","password":"Admin0701@"}`, "")
	if good.StatusCode != http.StatusOK {
		t.Fatalf("login status %d", good.StatusCode)
	}
	good.Body.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL+"/api/version", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer test-token")
	version, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer version.Body.Close()
	if version.StatusCode != http.StatusOK {
		t.Fatalf("version status %d", version.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(version.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["OS"] == "" {
		t.Fatalf("version payload missing OS: %#v", body)
	}
}

func TestUnknownTaskRejected(t *testing.T) {
	svc := NewService("test-token")
	server := httptest.NewServer(svc.Handler())
	defer server.Close()
	res := postJSON(t, server.URL+"/api/task", `{"kind":"session","id":"abc","action":"nope"}`, "test-token")
	defer res.Body.Close()
	if res.StatusCode != http.StatusBadGateway {
		t.Fatalf("status %d", res.StatusCode)
	}
}

func postJSON(t *testing.T, url, payload, token string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestLiteAPIs(t *testing.T) {
	t.Setenv("SLIVER_ROOT_DIR", t.TempDir())
	svc := NewService("test-token")
	server := httptest.NewServer(svc.Handler())
	defer server.Close()

	// start listener on an ephemeral port
	res := postJSON(t, server.URL+"/api/lite/listener/start", `{"host":"127.0.0.1","port":0}`, "test-token")
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("start status %d", res.StatusCode)
	}
	var startBody map[string]any
	if err := json.NewDecoder(res.Body).Decode(&startBody); err != nil {
		t.Fatal(err)
	}
	if startBody["addr"] == "" {
		t.Fatalf("missing addr: %#v", startBody)
	}

	// config contains an obfuscated config.h and a secret
	res2, err := apiGet(t, server.URL+"/api/lite/config", "test-token")
	if err != nil {
		t.Fatal(err)
	}
	defer res2.Body.Close()
	var cfg map[string]any
	if err := json.NewDecoder(res2.Body).Decode(&cfg); err != nil {
		t.Fatal(err)
	}
	cfgH, _ := cfg["configH"].(string)
	if !strings.Contains(cfgH, "CFG_URL_LEN") || strings.Contains(cfgH, "https://") {
		t.Fatalf("bad config.h: %q", cfgH)
	}

	// empty beacon list renders fine
	res3, err := apiGet(t, server.URL+"/api/lite/beacons", "test-token")
	if err != nil {
		t.Fatal(err)
	}
	defer res3.Body.Close()
	var beacons map[string]any
	if err := json.NewDecoder(res3.Body).Decode(&beacons); err != nil {
		t.Fatal(err)
	}
	if beacons["Beacons"] == nil {
		t.Fatalf("beacons payload: %#v", beacons)
	}

	// task to unknown beacon is rejected
	res4 := postJSON(t, server.URL+"/api/lite/task", `{"beaconId":"nope","type":"exec","cmd":"id"}`, "test-token")
	defer res4.Body.Close()
	if res4.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown beacon should be 400, got %d", res4.StatusCode)
	}

	// stop
	res5 := postJSON(t, server.URL+"/api/lite/listener/stop", `{}`, "test-token")
	defer res5.Body.Close()
	if res5.StatusCode != http.StatusOK {
		t.Fatalf("stop status %d", res5.StatusCode)
	}
}

func apiGet(t *testing.T, url, token string) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return http.DefaultClient.Do(req)
}
