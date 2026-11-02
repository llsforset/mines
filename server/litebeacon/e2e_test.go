//go:build sliver_e2e

package litebeacon

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestLiteImplantE2E builds the C implant in a container and walks it through
// a full lifecycle against a real listener. Run with:
//
//	LITE_E2E=1 go test -tags=server,go_sqlite,sliver_e2e ./server/litebeacon -run TestLiteImplantE2E -v -timeout 15m
func TestLiteImplantE2E(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}
	if os.Getenv("LITE_E2E") != "1" {
		t.Skip("set LITE_E2E=1 to run the container-based implant e2e")
	}

	implantDir, err := filepath.Abs(filepath.Join("..", "..", "implant", "lite"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(implantDir, "main.c")); err != nil {
		t.Skip("implant/lite sources not present")
	}

	t.Setenv("SLIVER_ROOT_DIR", t.TempDir())
	secrets, err := LoadSecrets(SecretsPath(os.Getenv("SLIVER_ROOT_DIR")))
	if err != nil {
		t.Fatal(err)
	}
	entry, _ := secrets.Latest()
	store := NewStore()
	store.SetIntervalPolicy(10, 5) // e2e 用快间隔策略，活跃轮 2.5~8.5 秒

	lis, err := Start(ListenerConfig{Host: "0.0.0.0", Port: 0}, store, secrets)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lis.Stop() })
	_, portStr, _ := net.SplitHostPort(lis.Addr().String())

	cfgH, err := GenerateConfigH(ConfigParams{
		URL:             fmt.Sprintf("https://host.docker.internal:%s/api/v2/sync", portStr),
		SecretB64:       entry.SecretB64,
		KeyName:         entry.KeyName,
		UserAgent:       "DeviceSync/2.0.7 (Linux x86_64)",
		BaseIntervalSec: 5, // fast loop for the test
	})
	if err != nil {
		t.Fatal(err)
	}

	// preserve any operator config.h, write the e2e one, restore afterwards
	configPath := filepath.Join(implantDir, "config.h")
	saved, hadSaved := readFile(t, configPath)
	t.Cleanup(func() {
		if hadSaved {
			_ = os.WriteFile(configPath, saved, 0o600)
		} else {
			_ = os.Remove(configPath)
		}
	})
	if err := os.WriteFile(configPath, []byte(cfgH), 0o600); err != nil {
		t.Fatal(err)
	}

	docker := func(args ...string) *exec.Cmd {
		cmd := exec.Command("docker", args...)
		cmd.Dir = implantDir
		return cmd
	}
	// LITE_E2E_IMAGE 复用现成镜像标签（跳过构建与平台强制）；
	// 默认走完整路径：构建 amd64 镜像并强制平台。
	image := os.Getenv("LITE_E2E_IMAGE")
	platformArgs := []string{}
	if image == "" {
		image = "sliver-lite-build"
		platformArgs = []string{"--platform", "linux/amd64"}
		if out, err := docker("build", "--platform", "linux/amd64", "-t", image, ".").CombinedOutput(); err != nil {
			t.Fatalf("docker build: %v\n%s", err, out)
		}
	}

	container := fmt.Sprintf("lite-e2e-%d", time.Now().UnixNano())
	runArgs := append([]string{"run", "--rm", "-d", "--name", container}, platformArgs...)
	runArgs = append(runArgs, "-v", implantDir+":/src", image,
		"sh", "-c", "sh compile.sh linux dist && exec ./dist/lite")
	if out, err := docker(runArgs...).CombinedOutput(); err != nil {
		t.Fatalf("docker run: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = docker("rm", "-f", container).Run() })

	// wait for the hello check-in
	var beaconID string
	deadline := time.Now().Add(3 * time.Minute)
	for time.Now().Before(deadline) {
		beacons := store.ListBeacons()
		if len(beacons) > 0 {
			beaconID = beacons[0].ID
			break
		}
		time.Sleep(2 * time.Second)
	}
	if beaconID == "" {
		t.Fatal("implant never checked in")
	}
	t.Logf("implant checked in: %s", beaconID)

	// queue an exec task and wait for the result
	marker := "hello-lite-e2e"
	if _, ok := store.QueueTask(beaconID, Task{Type: TaskExec, Cmd: "echo " + marker, TimeoutSec: 15}); !ok {
		t.Fatal("queue failed")
	}
	var results []Result
	deadline = time.Now().Add(3 * time.Minute)
	for time.Now().Before(deadline) {
		results = store.TakeResults(beaconID)
		if len(results) > 0 {
			break
		}
		time.Sleep(2 * time.Second)
	}
	if len(results) == 0 {
		t.Fatal("no exec result arrived")
	}
	if results[0].Kind != "exec" || !strings.Contains(string(results[0].Output), marker) {
		t.Fatalf("bad result: %#v", results[0])
	}
	t.Logf("exec result: %s", string(results[0].Output))

	// read a file too
	if _, ok := store.QueueTask(beaconID, Task{Type: TaskRead, Path: "/etc/hostname"}); !ok {
		t.Fatal("queue read failed")
	}
	deadline = time.Now().Add(3 * time.Minute)
	for time.Now().Before(deadline) {
		results = store.TakeResults(beaconID)
		if len(results) > 0 {
			break
		}
		time.Sleep(2 * time.Second)
	}
	if len(results) == 0 || results[0].Err != 0 || len(results[0].Output) == 0 {
		t.Fatalf("bad file result: %#v", results)
	}

	// exit task should stop the container process
	if _, ok := store.QueueTask(beaconID, Task{Type: TaskExit}); !ok {
		t.Fatal("queue exit failed")
	}
	deadline = time.Now().Add(2 * time.Minute)
	for time.Now().Before(deadline) {
		if len(store.ListBeacons()) == 0 {
			break
		}
		time.Sleep(2 * time.Second)
	}
	if len(store.ListBeacons()) != 0 {
		t.Fatal("exit task did not remove the beacon")
	}
}

func readFile(t *testing.T, path string) ([]byte, bool) {
	t.Helper()
	data, err := os.ReadFile(path)
	return data, err == nil
}
