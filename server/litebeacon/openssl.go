package litebeacon

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ulikunitz/xz"
)

// Bookworm's libssl.so.3 needs GLIBC_2.34. Zig's default linux-gnu libc is
// older and refuses that link, so Linux targets pin the bookworm ABI.
const (
	opensslDebVersion = "3.0.20-1~deb12u2"
	linuxGlibcABI     = "2.36"
)

var opensslOnce sync.Mutex

type linuxSSLArch struct {
	debArch string
	triple  string
}

func linuxSSLArchOf(goarch string) (linuxSSLArch, error) {
	switch goarch {
	case "amd64":
		return linuxSSLArch{"amd64", "x86_64-linux-gnu"}, nil
	case "arm64":
		return linuxSSLArch{"arm64", "aarch64-linux-gnu"}, nil
	default:
		return linuxSSLArch{}, fmt.Errorf("没有 %s 的 Linux OpenSSL", goarch)
	}
}

func opensslDebURL(pkg, debArch string) string {
	return "https://deb.debian.org/debian/pool/main/o/openssl/" + pkg + "_" + opensslDebVersion + "_" + debArch + ".deb"
}

func fetchDeb(url, dest string) error {
	var last error
	for attempt := 1; attempt <= 4; attempt++ {
		if err := fetchOnce(url, dest); err == nil {
			return nil
		} else {
			last = err
		}
		time.Sleep(time.Duration(attempt) * time.Second)
	}
	return last
}

// ensureLinuxOpenSSL downloads Debian bookworm libssl once and returns the
// include directory and the directory that holds libssl.so / libcrypto.so.
func ensureLinuxOpenSSL(goarch string) (includeDir, libDir string, err error) {
	arch, err := linuxSSLArchOf(goarch)
	if err != nil {
		return "", "", err
	}
	dest := filepath.Join(toolchainDir(), "openssl", "linux-"+goarch)
	if opensslReady(dest) {
		return filepath.Join(dest, "include"), filepath.Join(dest, "lib"), nil
	}
	opensslOnce.Lock()
	defer opensslOnce.Unlock()
	if opensslReady(dest) {
		return filepath.Join(dest, "include"), filepath.Join(dest, "lib"), nil
	}
	fmt.Printf("[*] 正在准备 Linux OpenSSL (%s) …\n", arch.debArch)
	tmp, err := os.MkdirTemp("", "openssl-deb-")
	if err != nil {
		return "", "", err
	}
	defer os.RemoveAll(tmp)
	extracted := filepath.Join(tmp, "root")
	if err := os.MkdirAll(extracted, 0o755); err != nil {
		return "", "", err
	}
	for _, pkg := range []string{"libssl3", "libssl-dev"} {
		deb := filepath.Join(tmp, pkg+".deb")
		if err := fetchDeb(opensslDebURL(pkg, arch.debArch), deb); err != nil {
			return "", "", fmt.Errorf("下载 %s 失败: %w", pkg, err)
		}
		if err := extractDeb(deb, extracted); err != nil {
			return "", "", err
		}
	}
	staging := dest + ".tmp"
	os.RemoveAll(staging)
	if err := installOpenSSLTree(extracted, staging, arch.triple); err != nil {
		os.RemoveAll(staging)
		return "", "", err
	}
	if err := os.WriteFile(filepath.Join(staging, "version"), []byte(opensslDebVersion+"\n"), 0o644); err != nil {
		return "", "", err
	}
	os.RemoveAll(dest)
	if err := os.Rename(staging, dest); err != nil {
		return "", "", err
	}
	return filepath.Join(dest, "include"), filepath.Join(dest, "lib"), nil
}

func opensslReady(dest string) bool {
	ver, err := os.ReadFile(filepath.Join(dest, "version"))
	if err != nil || strings.TrimSpace(string(ver)) != opensslDebVersion {
		return false
	}
	for _, name := range []string{
		filepath.Join(dest, "include", "openssl", "ssl.h"),
		filepath.Join(dest, "include", "openssl", "opensslconf.h"),
		filepath.Join(dest, "lib", "libssl.so"),
		filepath.Join(dest, "lib", "libcrypto.so"),
	} {
		if _, err := os.Stat(name); err != nil {
			return false
		}
	}
	return true
}

func installOpenSSLTree(extracted, dest, triple string) error {
	usr := filepath.Join(extracted, "usr")
	inc := filepath.Join(dest, "include", "openssl")
	if err := copyDirFiles(filepath.Join(usr, "include", "openssl"), inc); err != nil {
		return fmt.Errorf("OpenSSL 头文件不完整: %w", err)
	}
	if err := copyDirFiles(filepath.Join(usr, "include", triple, "openssl"), inc); err != nil {
		return fmt.Errorf("OpenSSL 架构头文件不完整: %w", err)
	}
	return copySharedLibs(filepath.Join(usr, "lib", triple), filepath.Join(dest, "lib"))
}

func copyDirFiles(src, dst string) error {
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if err := copyFileOrLink(filepath.Join(src, entry.Name()), filepath.Join(dst, entry.Name())); err != nil {
			return err
		}
	}
	return nil
}

func copySharedLibs(src, dst string) error {
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	n := 0
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, "libssl.so") && !strings.HasPrefix(name, "libcrypto.so") {
			continue
		}
		if err := copyFileOrLink(filepath.Join(src, name), filepath.Join(dst, name)); err != nil {
			return err
		}
		n++
	}
	if n == 0 {
		return fmt.Errorf("OpenSSL 包里没有 libssl.so")
	}
	return nil
}

func copyFileOrLink(src, dst string) error {
	info, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	os.Remove(dst)
	if info.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(src)
		if err != nil {
			return err
		}
		if filepath.IsAbs(target) {
			return fmt.Errorf("拒绝绝对符号链接 %s", target)
		}
		return os.Symlink(target, dst)
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	_, cerr := io.Copy(out, in)
	closeErr := out.Close()
	if cerr != nil {
		return cerr
	}
	return closeErr
}

func extractDeb(path, dest string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	magic := make([]byte, 8)
	if _, err := io.ReadFull(f, magic); err != nil || string(magic) != "!<arch>\n" {
		return fmt.Errorf("不是 deb 包: %s", path)
	}
	var dataOff, dataSize int64
	var dataName string
	for {
		hdr := make([]byte, 60)
		if _, err := io.ReadFull(f, hdr); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			}
			return err
		}
		if string(hdr[58:60]) != "`\n" {
			return fmt.Errorf("deb 头损坏")
		}
		name := strings.TrimRight(strings.TrimSpace(string(hdr[0:16])), "/")
		size, err := strconv.ParseInt(strings.TrimSpace(string(hdr[48:58])), 10, 64)
		if err != nil || size < 0 {
			return fmt.Errorf("deb 成员大小无效")
		}
		off, err := f.Seek(0, io.SeekCurrent)
		if err != nil {
			return err
		}
		if strings.HasPrefix(name, "data.tar") {
			dataOff, dataSize, dataName = off, size, name
		}
		skip := size
		if skip%2 == 1 {
			skip++
		}
		if _, err := f.Seek(skip, io.SeekCurrent); err != nil {
			return err
		}
	}
	if dataOff == 0 {
		return fmt.Errorf("deb 里没有 data.tar")
	}
	if _, err := f.Seek(dataOff, io.SeekStart); err != nil {
		return err
	}
	sr := io.NewSectionReader(f, dataOff, dataSize)
	var tr *tar.Reader
	switch {
	case strings.HasSuffix(dataName, ".xz"):
		xr, err := xz.NewReader(sr)
		if err != nil {
			return err
		}
		tr = tar.NewReader(xr)
	default:
		return fmt.Errorf("不支持的 deb 数据格式 %s", dataName)
	}
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
			out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
			if err != nil {
				return err
			}
			_, cerr := io.Copy(out, tr)
			out.Close()
			if cerr != nil {
				return cerr
			}
		case tar.TypeSymlink:
			if filepath.IsAbs(hdr.Linkname) {
				return fmt.Errorf("拒绝绝对符号链接 %s", hdr.Linkname)
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			os.Remove(target)
			if err := os.Symlink(hdr.Linkname, target); err != nil {
				return err
			}
		}
	}
}
