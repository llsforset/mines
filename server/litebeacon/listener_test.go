package litebeacon

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

func startTestListener(t *testing.T) (*Listener, *Store, *SecretRegistry, SecretEntry) {
	t.Helper()
	t.Setenv("SLIVER_ROOT_DIR", t.TempDir())
	secrets, err := LoadSecrets(filepath.Join(t.TempDir(), "secrets.json"))
	if err != nil {
		t.Fatal(err)
	}
	entry, ok := secrets.Latest()
	if !ok {
		t.Fatal("no secret")
	}
	store := NewStore()
	lis, err := Start(ListenerConfig{Host: "127.0.0.1", Port: 0}, store, secrets)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lis.Stop() })
	return lis, store, secrets, entry
}

func postCheckin(t *testing.T, addr, path string, entry SecretEntry, plain []byte) (*http.Response, []byte) {
	t.Helper()
	key := deriveKey(mustSecret(t, entry))
	body, err := sealBody(entry.KeyName, key, plain)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec
	resp, err := client.Post("https://"+addr+path, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, data
}

func mustSecret(t *testing.T, entry SecretEntry) []byte {
	t.Helper()
	secret, err := base64.StdEncoding.DecodeString(entry.SecretB64)
	if err != nil || len(secret) != 32 {
		t.Fatalf("bad secret entry: %#v", entry)
	}
	return secret
}

func TestListenerFullRoundTrip(t *testing.T) {
	lis, store, secrets, entry := startTestListener(t)
	addr := lis.Addr().String()
	now := uint64(time.Now().Unix())

	// hello check-in
	hello := encodeTLVs([]tlv{
		{Type: tlvBeaconID, Value: []byte("roundtrip-id-01")},
		{Type: tlvTimestamp, Value: u64b(now)},
		{Type: tlvHostname, Value: []byte("box")},
		{Type: tlvOS, Value: []byte("Linux 5.10")},
		{Type: tlvArch, Value: []byte("amd64")},
		{Type: tlvUsername, Value: []byte("root")},
		{Type: tlvPID, Value: u32b(1)},
	})
	resp, data := postCheckin(t, addr, DefaultPath, entry, hello)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("hello status %d body %s", resp.StatusCode, data)
	}
	beacons := store.ListBeacons()
	if len(beacons) != 1 || beacons[0].Info.Hostname != "box" {
		t.Fatalf("beacon not registered: %#v", beacons)
	}

	// queue a task, expect it delivered on the next check-in
	if _, ok := store.QueueTask("roundtrip-id-01", Task{Type: TaskExec, Cmd: "id", TimeoutSec: 10}); !ok {
		t.Fatal("queue failed")
	}
	resp, data = postCheckin(t, addr, DefaultPath, entry, encodeTLVs([]tlv{
		{Type: tlvBeaconID, Value: []byte("roundtrip-id-01")},
		{Type: tlvTimestamp, Value: u64b(uint64(time.Now().Unix()))},
	}))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("poll status %d", resp.StatusCode)
	}
	plain, _, _, err := openBody(data, secrets.Entries())
	if err != nil {
		t.Fatalf("response envelope: %v (%s)", err, data)
	}
	items, err := decodeTLVs(plain)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, it := range items {
		if it.Type == TaskExec && binary.LittleEndian.Uint32(it.Value[0:4]) == 1 && string(it.Value[6:]) == "id" {
			found = true
		}
	}
	if !found {
		t.Fatalf("task not delivered: %#v", items)
	}

	// deliver an exec result, read it via the store
	postCheckin(t, addr, DefaultPath, entry, encodeTLVs([]tlv{
		{Type: tlvBeaconID, Value: []byte("roundtrip-id-01")},
		{Type: tlvTimestamp, Value: u64b(uint64(time.Now().Unix()))},
		{Type: tlvExecRes, Value: append(append(u32b(1), u32b(0)...), []byte("uid=0(root)")...)},
	}))
	results := store.TakeResults("roundtrip-id-01")
	if len(results) != 1 || results[0].Kind != "exec" || string(results[0].Output) != "uid=0(root)" {
		t.Fatalf("results: %#v", results)
	}
}

func TestListenerCamouflage(t *testing.T) {
	lis, _, _, entry := startTestListener(t)
	addr := lis.Addr().String()
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec

	// GET → nginx-style 404 page
	resp, err := client.Get("https://" + addr + "/api/v2/sync")
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.Header.Get("Server") != "nginx" {
		t.Fatalf("GET cover page Server header wrong: %q", resp.Header.Get("Server"))
	}
	if resp.StatusCode != http.StatusNotFound || !bytes.Contains(page, []byte("nginx")) {
		t.Fatalf("GET cover page wrong: %d %s", resp.StatusCode, page)
	}

	// wrong path POST → 404 page
	body, _ := sealBody(entry.KeyName, deriveKey(mustSecret(t, entry)), []byte("x"))
	resp, err = client.Post("https://"+addr+"/other", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("wrong path status %d", resp.StatusCode)
	}

	// bad secret → 404 page
	forged := randomBytes(32)
	body, _ = sealBody("data", deriveKey(forged), []byte("x"))
	resp, err = client.Post("https://"+addr+DefaultPath, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("forged secret status %d", resp.StatusCode)
	}

	// replay → 404（线上重放 = 原样重发同一密文体，nonce 相同触发重放窗口）
	now := uint64(time.Now().Unix())
	plain := encodeTLVs([]tlv{
		{Type: tlvBeaconID, Value: []byte("replay-01")},
		{Type: tlvTimestamp, Value: u64b(now)},
	})
	replayBody, _ := sealBody(entry.KeyName, deriveKey(mustSecret(t, entry)), plain)
	resp, err = client.Post("https://"+addr+DefaultPath, "application/json", bytes.NewReader(replayBody))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first check-in failed: %d", resp.StatusCode)
	}
	resp, err = client.Post("https://"+addr+DefaultPath, "application/json", bytes.NewReader(replayBody))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("replay must be rejected with 404, got %d", resp.StatusCode)
	}

	// stale timestamp → 404
	stale := encodeTLVs([]tlv{
		{Type: tlvBeaconID, Value: []byte("stale-01")},
		{Type: tlvTimestamp, Value: u64b(now - 3600)},
	})
	resp, _ = postCheckin(t, addr, DefaultPath, entry, stale)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("stale timestamp must be rejected, got %d", resp.StatusCode)
	}
}

func TestExitTaskDeletesBeacon(t *testing.T) {
	lis, store, _, entry := startTestListener(t)
	addr := lis.Addr().String()
	beaconID := "exit-01"
	now := uint64(time.Now().Unix())
	resp, _ := postCheckin(t, addr, DefaultPath, entry, encodeTLVs([]tlv{
		{Type: tlvBeaconID, Value: []byte(beaconID)},
		{Type: tlvTimestamp, Value: u64b(now)},
	}))
	resp.Body.Close()
	_, _ = store.QueueTask(beaconID, Task{Type: TaskExit})
	resp, data := postCheckin(t, addr, DefaultPath, entry, encodeTLVs([]tlv{
		{Type: tlvBeaconID, Value: []byte(beaconID)},
		{Type: tlvTimestamp, Value: u64b(uint64(time.Now().Unix()))},
	}))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("exit delivery status %d body %s", resp.StatusCode, data)
	}
	if beacons := store.ListBeacons(); len(beacons) != 0 {
		t.Fatalf("exit task must remove beacon: %#v", beacons)
	}
}
