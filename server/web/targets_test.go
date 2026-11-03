package web

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAliasBookPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "target-aliases.json")
	book := loadAliasBook(path)
	if err := book.set("abc", "财务机"); err != nil {
		t.Fatal(err)
	}
	again := loadAliasBook(path)
	got := again.snapshot()
	if got["abc"] != "财务机" {
		t.Fatalf("alias = %#v", got)
	}
	again.delete("abc")
	if _, ok := loadAliasBook(path).snapshot()["abc"]; ok {
		t.Fatal("alias was not deleted")
	}
}

func TestCleanAlias(t *testing.T) {
	if _, err := cleanAlias("  "); err == nil {
		t.Fatal("blank alias should fail")
	}
	name, err := cleanAlias("  财务-01 ")
	if err != nil || name != "财务-01" {
		t.Fatalf("name %q err %v", name, err)
	}
	if _, err := cleanAlias(strings.Repeat("名", 33)); err == nil {
		t.Fatal("long alias should fail")
	}
}

func TestTargetAliasAPI(t *testing.T) {
	t.Setenv("SLIVER_ROOT_DIR", t.TempDir())
	svc := NewService("test-token")
	server := httptest.NewServer(svc.Handler())
	defer server.Close()

	missing := postJSON(t, server.URL+"/api/targets/rename", `{"kind":"session","id":"missing-session","name":"web"}`, "test-token")
	defer missing.Body.Close()
	if missing.StatusCode != http.StatusBadRequest {
		t.Fatalf("missing session status %d", missing.StatusCode)
	}

	blank := postJSON(t, server.URL+"/api/targets/rename", `{"kind":"lite","id":"lite-1","name":"  "}`, "test-token")
	defer blank.Body.Close()
	if blank.StatusCode != http.StatusBadRequest {
		t.Fatalf("blank alias status %d", blank.StatusCode)
	}

	badKind := postJSON(t, server.URL+"/api/targets/remove", `{"kind":"nope","id":"lite-1"}`, "test-token")
	defer badKind.Body.Close()
	if badKind.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad kind status %d", badKind.StatusCode)
	}

	res, err := apiGet(t, server.URL+"/api/targets/aliases", "test-token")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var body map[string]any
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	aliases, _ := body["aliases"].(map[string]any)
	if aliases == nil {
		t.Fatalf("aliases payload %#v", body)
	}

	js, err := http.Get(server.URL + "/app.js")
	if err != nil {
		t.Fatal(err)
	}
	defer js.Body.Close()
	script, err := io.ReadAll(js.Body)
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range []string{"点击修改别名", "/api/targets/remove", "/api/targets/rename"} {
		if !strings.Contains(string(script), needle) {
			t.Fatalf("app.js missing %q", needle)
		}
	}
	if strings.Contains(string(script), "复制编号") {
		t.Fatal("copy-id button should be gone")
	}
	cssRes, err := http.Get(server.URL + "/app.css")
	if err != nil {
		t.Fatal(err)
	}
	defer cssRes.Body.Close()
	css, err := io.ReadAll(cssRes.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(css), "#2fbe63") || !strings.Contains(string(css), "#e24b4b") {
		t.Fatal("status colors missing from app.css")
	}
	if _, err := os.Stat(filepath.Join(os.Getenv("SLIVER_ROOT_DIR"), "target-aliases.json")); err == nil {
		t.Fatal("failed rename should not create an alias file")
	}
}
