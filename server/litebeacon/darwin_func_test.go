//go:build darwin

package litebeacon

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestDarwinImplantStillWorks compiles the real C implant and checks the
// paths operators actually use: check-in, command output, file read, and exit.
func TestDarwinImplantStillWorks(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("host clang build is darwin-only")
	}
	if _, err := exec.LookPath("clang"); err != nil {
		t.Skip("clang not available")
	}

	root := t.TempDir()
	t.Setenv("SLIVER_ROOT_DIR", root)
	secrets, err := LoadSecrets(filepath.Join(root, "litebeacon", "secrets.json"))
	if err != nil {
		t.Fatal(err)
	}
	entry, ok := secrets.Latest()
	if !ok {
		t.Fatal("no secret")
	}
	store := NewStore()
	store.SetIntervalPolicy(5, 5)
	lis, err := Start(ListenerConfig{Host: "127.0.0.1", Port: 0, Path: "/api/v1/orders"}, store, secrets)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lis.Stop() })
	_, port, _ := net.SplitHostPort(lis.Addr().String())

	src := filepath.Join("..", "..", "implant", "lite")
	build := t.TempDir()
	for _, name := range []string{"main.c", "darwin.c", "port.h"} {
		data, err := os.ReadFile(filepath.Join(src, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(build, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := GenerateConfigH(ConfigParams{
		URL:             fmt.Sprintf("https://127.0.0.1:%s/api/v1/orders", port),
		SecretB64:       entry.SecretB64,
		KeyName:         entry.KeyName,
		UserAgent:       "DeviceSync/2.0.7 (Linux x86_64)",
		BaseIntervalSec: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(build, "config.h"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(build, "lite")
	cmd := exec.Command("clang", "-O2", "-o", bin, "main.c", "darwin.c",
		"-framework", "Security", "-framework", "CoreFoundation")
	cmd.Dir = build
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("clang: %v\n%s", err, out)
	}
	raw, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(keyCtx)) {
		t.Fatal("implant binary contains plaintext key context")
	}

	proc := exec.Command(bin)
	proc.Dir = build
	if err := proc.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan struct{})
	go func() {
		_, _ = proc.Process.Wait()
		close(exited)
	}()
	t.Cleanup(func() {
		if proc.Process != nil {
			_ = proc.Process.Kill()
		}
		<-exited
	})

	beaconID := waitBeacon(t, store, 45*time.Second)
	if _, ok := store.QueueTask(beaconID, Task{Type: TaskExec, Cmd: "echo hello-lite-func", TimeoutSec: 5}); !ok {
		t.Fatal("queue echo failed")
	}
	got := waitResult(t, store, beaconID, 40*time.Second)
	if got.Kind != "exec" || got.Exit != 0 || !strings.Contains(string(got.Output), "hello-lite-func") {
		t.Fatalf("echo result: %#v %q", got, got.Output)
	}

	file := filepath.Join(build, "sample.txt")
	if err := os.WriteFile(file, []byte("lite-func-file"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.QueueTask(beaconID, Task{Type: TaskRead, Path: file}); !ok {
		t.Fatal("queue read failed")
	}
	got = waitResult(t, store, beaconID, 40*time.Second)
	if got.Kind != "read" || got.Err != 0 || string(got.Output) != "lite-func-file" {
		t.Fatalf("file result: %#v %q", got, got.Output)
	}

	big := bytes.Repeat([]byte("K"), fileChunkSize+123)
	bigPath := filepath.Join(build, "chunk.bin")
	if err := os.WriteFile(bigPath, big, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.QueueTask(beaconID, Task{Type: TaskRead, Path: bigPath}); !ok {
		t.Fatal("queue chunked read failed")
	}
	got = waitResult(t, store, beaconID, 40*time.Second)
	if got.Kind != "read" || got.Err != 0 || !bytes.Equal(got.Output, big) {
		t.Fatalf("chunked file: err=%d n=%d", got.Err, len(got.Output))
	}

	// 目录浏览：列 build 目录，应该看到刚才两个文件和编译出来的程序
	if _, ok := store.QueueTask(beaconID, Task{Type: TaskListDir, Path: build}); !ok {
		t.Fatal("queue listdir failed")
	}
	deadline := time.Now().Add(40 * time.Second)
	var listing DirListing
	for {
		var found bool
		listing, found, _ = store.DirStatus(beaconID, build)
		if found || time.Now().After(deadline) {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if listing.Err != 0 || listing.Truncated {
		t.Fatalf("dir listing: %#v", listing)
	}
	names := map[string]bool{}
	for _, entry := range listing.Entries {
		names[entry.Name] = entry.IsDir
	}
	if isdir, ok := names["sample.txt"]; !ok || isdir {
		t.Fatalf("sample.txt missing or wrong kind: %#v", listing.Entries)
	}
	if isdir, ok := names["chunk.bin"]; !ok || isdir {
		t.Fatalf("chunk.bin missing or wrong kind: %#v", listing.Entries)
	}
	if isdir, ok := names["lite"]; !ok || isdir {
		t.Fatalf("compiled binary missing: %#v", listing.Entries)
	}

	// 对文件列目录 → err 3（不是目录）
	if _, ok := store.QueueTask(beaconID, Task{Type: TaskListDir, Path: file}); !ok {
		t.Fatal("queue listdir on file failed")
	}
	fileDeadline := time.Now().Add(20 * time.Second)
	for {
		var found bool
		listing, found, _ = store.DirStatus(beaconID, file)
		if found || time.Now().After(fileDeadline) {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if listing.Err != 3 {
		t.Fatalf("listing a file should be err 3: %#v", listing)
	}

	// —— 阶段 2：写回 / 建目录 / 改名 / 删除 ——
	waitFs := func(d time.Duration) Result {
		t.Helper()
		deadline := time.Now().Add(d)
		for time.Now().Before(deadline) {
			for _, r := range store.TakeResults(beaconID) {
				if r.Kind == "fs" {
					return r
				}
			}
			time.Sleep(200 * time.Millisecond)
		}
		t.Fatal("timed out waiting fs result")
		return Result{}
	}
	refreshList := func() []DirEntry {
		t.Helper()
		prevAt := time.Time{}
		if old, found, _ := store.DirStatus(beaconID, build); found {
			prevAt = old.At
		}
		if _, ok := store.QueueTask(beaconID, Task{Type: TaskListDir, Path: build}); !ok {
			t.Fatal("queue listdir")
		}
		deadline := time.Now().Add(40 * time.Second)
		for {
			ls, found, _ := store.DirStatus(beaconID, build)
			if found && ls.At.After(prevAt) {
				if ls.Err != 0 {
					t.Fatalf("refresh listdir: %#v", ls)
				}
				return ls.Entries
			}
			if time.Now().After(deadline) {
				t.Fatalf("refresh listdir timed out: %#v", ls)
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
	madePath := filepath.Join(build, "made.txt")
	if _, ok := store.QueueTask(beaconID, Task{Type: TaskWrite, Path: madePath, Data: []byte("made-by-fs-op"), Force: true}); !ok {
		t.Fatal("queue write")
	}
	if r := waitFs(30 * time.Second); r.Err != 0 {
		t.Fatalf("write new file: %#v", r)
	}
	if _, ok := store.QueueTask(beaconID, Task{Type: TaskRead, Path: madePath}); !ok {
		t.Fatal("queue read back")
	}
	got = waitResult(t, store, beaconID, 40*time.Second)
	if got.Err != 0 || string(got.Output) != "made-by-fs-op" {
		t.Fatalf("read back written file: %#v %q", got, got.Output)
	}

	// 冲突校验：期望值不对 → err 4，且内容不变
	var madeEntry DirEntry
	madeFound := false
	for _, e := range refreshList() {
		if e.Name == "made.txt" {
			madeEntry, madeFound = e, true
		}
	}
	if !madeFound {
		t.Fatal("made.txt missing from listing")
	}
	if _, ok := store.QueueTask(beaconID, Task{Type: TaskWrite, Path: madePath,
		Data: []byte("conflict"), ExpectSize: int64(madeEntry.Size) + 999, ExpectMTime: madeEntry.ModTime}); !ok {
		t.Fatal("queue conflict write")
	}
	if r := waitFs(30 * time.Second); r.Err != 4 {
		t.Fatalf("conflict write should be err 4: %#v", r)
	}
	if _, ok := store.QueueTask(beaconID, Task{Type: TaskRead, Path: madePath}); !ok {
		t.Fatal("queue read after conflict")
	}
	got = waitResult(t, store, beaconID, 40*time.Second)
	if string(got.Output) != "made-by-fs-op" {
		t.Fatalf("conflict write must not change content: %q", got.Output)
	}

	// 期望值正确 → 覆盖成功
	if _, ok := store.QueueTask(beaconID, Task{Type: TaskWrite, Path: madePath,
		Data: []byte("overwritten-ok"), ExpectSize: int64(madeEntry.Size), ExpectMTime: madeEntry.ModTime}); !ok {
		t.Fatal("queue checked write")
	}
	if r := waitFs(30 * time.Second); r.Err != 0 {
		t.Fatalf("checked overwrite: %#v", r)
	}
	if _, ok := store.QueueTask(beaconID, Task{Type: TaskRead, Path: madePath}); !ok {
		t.Fatal("queue read back 2")
	}
	got = waitResult(t, store, beaconID, 40*time.Second)
	if string(got.Output) != "overwritten-ok" {
		t.Fatalf("checked overwrite content: %q", got.Output)
	}

	// mkdir → mv → rm
	subDir := filepath.Join(build, "subdir")
	if _, ok := store.QueueTask(beaconID, Task{Type: TaskMkdir, Path: subDir}); !ok {
		t.Fatal("queue mkdir")
	}
	if r := waitFs(30 * time.Second); r.Err != 0 {
		t.Fatalf("mkdir: %#v", r)
	}
	seen := false
	for _, e := range refreshList() {
		if e.Name == "subdir" && e.IsDir {
			seen = true
		}
	}
	if !seen {
		t.Fatal("subdir not in listing")
	}
	if _, ok := store.QueueTask(beaconID, Task{Type: TaskMv, Path: madePath, Dst: filepath.Join(build, "renamed.txt")}); !ok {
		t.Fatal("queue mv")
	}
	if r := waitFs(30 * time.Second); r.Err != 0 {
		t.Fatalf("mv: %#v", r)
	}
	names = map[string]bool{}
	for _, e := range refreshList() {
		names[e.Name] = e.IsDir
	}
	if _, ok := names["made.txt"]; ok {
		t.Fatalf("mv left the old name: %#v", names)
	}
	if isdir, ok := names["renamed.txt"]; !ok || isdir {
		t.Fatalf("renamed.txt missing: %#v", names)
	}
	if _, ok := store.QueueTask(beaconID, Task{Type: TaskRm, Path: filepath.Join(build, "renamed.txt")}); !ok {
		t.Fatal("queue rm")
	}
	if r := waitFs(30 * time.Second); r.Err != 0 {
		t.Fatalf("rm file: %#v", r)
	}
	if _, ok := store.QueueTask(beaconID, Task{Type: TaskRm, Path: subDir, Recursive: true}); !ok {
		t.Fatal("queue rm -r")
	}
	if r := waitFs(30 * time.Second); r.Err != 0 {
		t.Fatalf("rm -r: %#v", r)
	}
	names = map[string]bool{}
	for _, e := range refreshList() {
		names[e.Name] = e.IsDir
	}
	if _, ok := names["renamed.txt"]; ok {
		t.Fatalf("rm not reflected: %#v", names)
	}
	if _, ok := names["subdir"]; ok {
		t.Fatalf("rm -r not reflected: %#v", names)
	}

	if _, ok := store.QueueTask(beaconID, Task{Type: TaskRead, Path: build}); !ok {
		t.Fatal("queue dir read failed")
	}
	got = waitResult(t, store, beaconID, 20*time.Second)
	if got.Kind != "read" || got.Err == 0 {
		t.Fatalf("directory read should fail closed: %#v", got)
	}

	if _, ok := store.QueueTask(beaconID, Task{Type: TaskExit}); !ok {
		t.Fatal("queue exit failed")
	}
	select {
	case <-time.After(30 * time.Second):
		t.Fatal("exit task did not stop the implant")
	case <-exited:
	}
}

func waitBeacon(t *testing.T, store *Store, d time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		beacons := store.ListBeacons()
		if len(beacons) == 1 {
			return beacons[0].ID
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("implant never checked in: %#v", store.ListBeacons())
	return ""
}

func waitResult(t *testing.T, store *Store, id string, d time.Duration) Result {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		results := store.TakeResults(id)
		if len(results) > 0 {
			return results[0]
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatal("timed out waiting for a result")
	return Result{}
}
