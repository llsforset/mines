package litebeacon

import "testing"

func TestZigArchiveNames(t *testing.T) {
	url, name, err := zigArchive("darwin", "arm64")
	if err != nil {
		t.Fatal(err)
	}
	if name != "zig-aarch64-macos-0.17.0.tar.xz" || url != "https://ziglang.org/download/0.17.0/"+name {
		t.Fatalf("darwin archive: %s %s", url, name)
	}
	_, name, err = zigArchive("windows", "amd64")
	if err != nil || name != "zig-x86_64-windows-0.17.0.zip" {
		t.Fatalf("windows archive: %s %v", name, err)
	}
	if _, _, err := zigArchive("darwin", "386"); err == nil {
		t.Fatal("386 should not have a zig archive")
	}
}
