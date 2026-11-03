//go:build darwin

package litebeacon

import (
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
