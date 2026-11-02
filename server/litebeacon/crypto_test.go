package litebeacon

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

func TestSealOpenRoundTrip(t *testing.T) {
	secret := randomBytes(32)
	key := deriveKey(secret)
	plain := []byte("hello-lite")
	body, err := sealBody("data", key, plain)
	if err != nil {
		t.Fatal(err)
	}
	var env map[string]string
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatal(err)
	}
	if len(env) != 1 {
		t.Fatalf("envelope has %d fields, want 1", len(env))
	}
	got, matched, _, err := openBody(body, []SecretEntry{{
		SecretB64: base64.StdEncoding.EncodeToString(secret),
		KeyName:   "data",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("round trip mismatch: %q", got)
	}
	if matched.KeyName != "data" {
		t.Fatalf("matched wrong entry: %#v", matched)
	}
}

func TestOpenBodyTriesAllSecrets(t *testing.T) {
	secretA := randomBytes(32)
	secretB := randomBytes(32)
	body, err := sealBody("token", deriveKey(secretB), []byte("payload-xyz"))
	if err != nil {
		t.Fatal(err)
	}
	entries := []SecretEntry{
		{SecretB64: base64.StdEncoding.EncodeToString(secretA), KeyName: "a"},
		{SecretB64: base64.StdEncoding.EncodeToString(secretB), KeyName: "b"},
	}
	got, matched, _, err := openBody(body, entries)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("payload-xyz")) || matched.KeyName != "b" {
		t.Fatalf("wrong match: %#v", matched)
	}
}

func TestOpenBodyRejectsGarbage(t *testing.T) {
	entries := []SecretEntry{{SecretB64: base64.StdEncoding.EncodeToString(randomBytes(32))}}
	for _, bad := range []string{`{}`, `{"a":"x","b":"y"}`, `not json`, `{"a":"!!not-base64!!"}`, `{"a":""}`} {
		if _, _, _, err := openBody([]byte(bad), entries); err == nil {
			t.Fatalf("expected error for %q", bad)
		}
	}
}

func TestDerivedKeyIsContextual(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	k1 := deriveKey(secret)
	k2 := deriveKey(append(append([]byte{}, secret...), 0))
	if k1 == k2 {
		t.Fatal("context separation broken")
	}
}

func TestMaxClockSkew(t *testing.T) {
	if maxClockSkew != 300*time.Second {
		t.Fatalf("maxClockSkew = %v", maxClockSkew)
	}
}
