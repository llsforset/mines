package litebeacon

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestEncodeDecodeTLVs(t *testing.T) {
	items := []tlv{
		{Type: 0x01, Value: []byte("abcdef0123456789")},
		{Type: 0x02, Value: []byte{1, 2, 3, 4, 5, 6, 7, 8}},
		{Type: 0x0f, Value: bytes.Repeat([]byte{0xAA}, 300)},
	}
	encoded := encodeTLVs(items)
	decoded, err := decodeTLVs(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != len(items) {
		t.Fatalf("decoded %d items, want %d", len(decoded), len(items))
	}
	for i := range items {
		if decoded[i].Type != items[i].Type || !bytes.Equal(decoded[i].Value, items[i].Value) {
			t.Fatalf("item %d mismatch: %#v", i, decoded[i])
		}
	}
}

func TestDecodeTLVsRejectsTruncation(t *testing.T) {
	if _, err := decodeTLVs([]byte{0x01, 0x05, 0x00, 'a'}); err == nil {
		t.Fatal("expected truncation error")
	}
	// declared 0xFF00 bytes but only 1 present — also truncation
	if _, err := decodeTLVs([]byte{0x01, 0x00, 0xFF, 'a'}); err == nil {
		t.Fatal("expected truncation error")
	}
}

func TestBuildTaskPayloadRejectsOversizeValue(t *testing.T) {
	long := strings.Repeat("a", 0xFFFF+1)
	if _, err := buildTaskPayload([]Task{{ID: 1, Type: TaskExec, Cmd: long, TimeoutSec: 1}}, 0); err == nil {
		t.Fatal("expected oversize rejection")
	}
}

func TestParseCheckin(t *testing.T) {
	now := uint64(1770000000)
	plain := encodeTLVs([]tlv{
		{Type: tlvBeaconID, Value: []byte("0123456789abcdef")},
		{Type: tlvTimestamp, Value: u64b(now)},
		{Type: tlvHostname, Value: []byte("web01")},
		{Type: tlvOS, Value: []byte("Linux 5.10")},
		{Type: tlvArch, Value: []byte("amd64")},
		{Type: tlvUsername, Value: []byte("root")},
		{Type: tlvPID, Value: u32b(4242)},
		{Type: tlvExecRes, Value: append(append(u32b(7), u32b(0)...), []byte("id output")...)},
		{Type: tlvFileRes, Value: append(append(u32b(9), 0x00), []byte("file-bytes")...)},
	})
	ci, err := parseCheckin(plain)
	if err != nil {
		t.Fatal(err)
	}
	if ci.BeaconID != "0123456789abcdef" || ci.TS != now {
		t.Fatalf("bad id/ts: %#v", ci)
	}
	if ci.Info == nil || ci.Info.Hostname != "web01" || ci.Info.Username != "root" || ci.Info.PID != 4242 {
		t.Fatalf("bad info: %#v", ci.Info)
	}
	if len(ci.Execs) != 1 || ci.Execs[0].TaskID != 7 || ci.Execs[0].Exit != 0 || string(ci.Execs[0].Output) != "id output" {
		t.Fatalf("bad exec result: %#v", ci.Execs)
	}
	if len(ci.Files) != 1 || ci.Files[0].TaskID != 9 || string(ci.Files[0].Content) != "file-bytes" {
		t.Fatalf("bad file result: %#v", ci.Files)
	}
}

func TestParseCheckinRequiresIDAndTS(t *testing.T) {
	if _, err := parseCheckin(encodeTLVs([]tlv{{Type: tlvBeaconID, Value: []byte("x")}})); err == nil {
		t.Fatal("expected missing timestamp error")
	}
	if _, err := parseCheckin(encodeTLVs([]tlv{{Type: tlvTimestamp, Value: u64b(1)}})); err == nil {
		t.Fatal("expected missing id error")
	}
}

func TestParseCheckinNoHello(t *testing.T) {
	plain := encodeTLVs([]tlv{
		{Type: tlvBeaconID, Value: []byte("0123456789abcdef")},
		{Type: tlvTimestamp, Value: u64b(1770000000)},
	})
	ci, err := parseCheckin(plain)
	if err != nil {
		t.Fatal(err)
	}
	if ci.Info != nil {
		t.Fatalf("info should be nil without hello fields: %#v", ci.Info)
	}
}

func TestBuildTaskPayload(t *testing.T) {
	tasks := []Task{
		{ID: 1, Type: TaskExec, Cmd: "id", TimeoutSec: 30},
		{ID: 2, Type: TaskRead, Path: "/etc/hostname"},
		{ID: 3, Type: TaskSleep, IntervalSec: 180, JitterPct: 10},
		{ID: 4, Type: TaskExit},
	}
	payload, err := buildTaskPayload(tasks, 5)
	if err != nil {
		t.Fatal(err)
	}
	items, err := decodeTLVs(payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 5 {
		t.Fatalf("got %d items (incl. pad), want 5", len(items))
	}
	if items[0].Type != TaskExec || u32(items[0].Value[0:4]) != 1 ||
		binary.LittleEndian.Uint16(items[0].Value[4:6]) != 30 {
		t.Fatalf("bad exec task: %#v", items[0])
	}
	if string(items[0].Value[6:]) != "id" {
		t.Fatalf("bad exec cmd: %q", items[0].Value[6:])
	}
	if items[1].Type != TaskRead || string(items[1].Value[4:]) != "/etc/hostname" {
		t.Fatalf("bad read task: %#v", items[1])
	}
	if items[2].Type != TaskSleep || u32(items[2].Value[0:4]) != 180 || items[2].Value[4] != 10 {
		t.Fatalf("bad sleep task: %#v", items[2])
	}
	if items[3].Type != TaskExit || len(items[3].Value) != 0 {
		t.Fatalf("bad exit task: %#v", items[3])
	}
	if items[4].Type != tlvPad || len(items[4].Value) != 5 {
		t.Fatalf("bad pad: %#v", items[4])
	}
}

func u64b(v uint64) []byte {
	b := make([]byte, 8)
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
	b[4] = byte(v >> 32)
	b[5] = byte(v >> 40)
	b[6] = byte(v >> 48)
	b[7] = byte(v >> 56)
	return b
}
func u32b(v uint32) []byte {
	b := make([]byte, 4)
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
	return b
}
func u32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}
