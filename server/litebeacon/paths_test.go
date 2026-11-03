package litebeacon

import "testing"

func TestNormalizePathRejectsSelfDescribingNames(t *testing.T) {
	if _, err := NormalizePath("/api/v1/orders"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"/lite/checkin", "/api/beacon", "/c2/sync", "../etc", ""} {
		if bad == "" {
			continue
		}
		if _, err := NormalizePath(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	got, err := NormalizePath("")
	if err != nil || got != DefaultPath {
		t.Fatalf("empty path: %q %v", got, err)
	}
}
