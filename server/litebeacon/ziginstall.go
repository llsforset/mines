package litebeacon

import (
	"archive/tar"
	"archive/zip"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/bishopfox/sliver/server/assets"
	"github.com/ulikunitz/xz"
)

const zigVersion = "0.17.0"

var zigEnsure sync.Mutex

// EnsureZig returns a usable zig binary, downloading the official toolchain
// into the server app directory when it is not already installed.
func EnsureZig() (string, error) {
	if p, err := findZig(); err == nil {
		return p, nil
	}
	zigEnsure.Lock()
	defer zigEnsure.Unlock()
	if p, err := findZig(); err == nil {
		return p, nil
	}
	fmt.Printf("[*] 没有找到 Zig，开始下载 %s …\n", zigVersion)
	path, err := downloadZig()
	if err != nil {
		return "", err
	}
	fmt.Printf("[*] Zig 已就绪: %s\n", path)
	return path, nil
}

func findZig() (string, error) {
	if p := os.Getenv("ZIG"); p != "" {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	if p, err := exec.LookPath("zig"); err == nil {
		return p, nil
	}
	recorded := filepath.Join(toolchainDir(), "zig-path")
	if data, err := os.ReadFile(recorded); err == nil {
		p := strings.TrimSpace(string(data))
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	return "", fmt.Errorf("zig 未安装")
}

func toolchainDir() string {
	return filepath.Join(assets.GetRootAppDir(), "toolchains")
}

func zigArchive(goos, goarch string) (url, name string, err error) {
	arch := map[string]string{"amd64": "x86_64", "arm64": "aarch64"}[goarch]
	if arch == "" {
		return "", "", fmt.Errorf("没有 %s/%s 的 Zig 安装包", goos, goarch)
	}
	var osName, ext string
	switch goos {
	case "darwin":
		osName, ext = "macos", ".tar.xz"
	case "linux":
		osName, ext = "linux", ".tar.xz"
	case "windows":
		osName, ext = "windows", ".zip"
	default:
		return "", "", fmt.Errorf("没有 %s 的 Zig 安装包", goos)
	}
	name = fmt.Sprintf("zig-%s-%s-%s%s", arch, osName, zigVersion, ext)
	return "https://ziglang.org/download/" + zigVersion + "/" + name, name, nil
}

func downloadZig() (string, error) {
	url, name, err := zigArchive(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return "", err
	}
	dir := toolchainDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	tmp := filepath.Join(dir, name+".partial")
	if err := fetch(url, tmp); err != nil {
		return "", err
	}
	extractDir := filepath.Join(dir, "zig-"+zigVersion)
	os.RemoveAll(extractDir)
	if err := os.MkdirAll(extractDir, 0o755); err != nil {
		return "", err
	}
	if strings.HasSuffix(name, ".zip") {
		err = unzip(tmp, extractDir)
	} else {
		err = untarXZ(tmp, extractDir)
	}
	os.Remove(tmp)
	if err != nil {
		return "", err
	}
	bin, err := findZigBinary(extractDir)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, "zig-path"), []byte(bin+"\n"), 0o644); err != nil {
		return "", err
	}
	return bin, nil
}

func fetch(url, dest string) error {
	var last error
	for attempt := 1; attempt <= 8; attempt++ {
		err := fetchOnce(url, dest)
		if err == nil {
			return nil
		}
		last = err
		fmt.Printf("[*] Zig 下载中断，第 %d 次重试: %v\n", attempt, err)
		time.Sleep(time.Duration(attempt) * 2 * time.Second)
	}
	return fmt.Errorf("下载 Zig 失败: %w", last)
}

func fetchOnce(url, dest string) error {
	var offset int64
	if st, err := os.Stat(dest); err == nil {
		offset = st.Size()
	}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	if offset > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", offset))
	}
	client := &http.Client{Timeout: 45 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		return fmt.Errorf("HTTP %s", resp.Status)
	}
	flags := os.O_CREATE | os.O_WRONLY
	got := int64(0)
	if resp.StatusCode == http.StatusPartialContent {
		flags |= os.O_APPEND
		got = offset
	} else {
		flags |= os.O_TRUNC
	}
	f, err := os.OpenFile(dest, flags, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	buf := make([]byte, 256*1024)
	next := ((got / (5 << 20)) + 1) * (5 << 20)
	total := resp.ContentLength
	if resp.StatusCode == http.StatusPartialContent && total > 0 {
		total += got
	}
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := f.Write(buf[:n]); werr != nil {
				return werr
			}
			got += int64(n)
			if got >= next {
				if total > 0 {
					fmt.Printf("[*] Zig 下载中 %d%%\n", got*100/total)
				} else {
					fmt.Printf("[*] Zig 已下载 %dMB\n", got>>20)
				}
				next += 5 << 20
			}
		}
		if rerr == io.EOF {
			return nil
		}
		if rerr != nil {
			return rerr
		}
	}
}

func untarXZ(path, dest string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	xr, err := xz.NewReader(f)
	if err != nil {
		return err
	}
	tr := tar.NewReader(xr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		target, err := safeJoin(dest, hdr.Name)
		if err != nil {
			return err
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			mode := os.FileMode(hdr.Mode) & 0o777
			if mode == 0 {
				mode = 0o644
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
			if err != nil {
				return err
			}
			_, cerr := io.Copy(out, tr)
			out.Close()
			if cerr != nil {
				return cerr
			}
		}
	}
}

func unzip(path, dest string) error {
	r, err := zip.OpenReader(path)
	if err != nil {
		return err
	}
	defer r.Close()
	for _, file := range r.File {
		target, err := safeJoin(dest, file.Name)
		if err != nil {
			return err
		}
		if file.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		rc, err := file.Open()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, file.Mode())
		if err != nil {
			rc.Close()
			return err
		}
		_, cerr := io.Copy(out, rc)
		out.Close()
		rc.Close()
		if cerr != nil {
			return cerr
		}
	}
	return nil
}

func safeJoin(root, name string) (string, error) {
	name = strings.TrimPrefix(filepath.ToSlash(name), "/")
	if name == "" {
		return "", fmt.Errorf("压缩包路径为空")
	}
	target := filepath.Join(root, filepath.FromSlash(name))
	rel, err := filepath.Rel(root, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("压缩包路径越界: %s", name)
	}
	return target, nil
}

func findZigBinary(root string) (string, error) {
	var found string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() || found != "" {
			return err
		}
		base := info.Name()
		if base == "zig" || base == "zig.exe" {
			found = path
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	if found == "" {
		return "", fmt.Errorf("安装包里没有 zig 可执行文件")
	}
	return found, nil
}
