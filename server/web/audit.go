package web

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/bishopfox/sliver/server/assets"
)

// AuditEntry is one row in the operator trail: every file operation on a
// target (download / write / rm / mv / mkdir / upload) gets recorded.
type AuditEntry struct {
	At     time.Time `json:"At"`
	Target string    `json:"Target"` // lite:<id> / session:<id> / beacon:<id>
	Op     string    `json:"Op"`
	Path   string    `json:"Path"`
	Dst    string    `json:"Dst,omitempty"`
	Size   int64     `json:"Size,omitempty"`
	Err    uint8     `json:"Err"`
	Msg    string    `json:"Msg,omitempty"`
}

// auditTrail is an append-only JSONL file under the files archive.
type auditTrail struct {
	mutex sync.Mutex
	path  string
}

var audit = &auditTrail{}

func (a *auditTrail) file() string {
	if a.path == "" {
		a.path = filepath.Join(assets.GetRootAppDir(), "files", "audit.jsonl")
	}
	return a.path
}

func (a *auditTrail) Append(entries ...AuditEntry) {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	if err := os.MkdirAll(filepath.Dir(a.file()), 0o700); err != nil {
		return
	}
	f, err := os.OpenFile(a.file(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	for _, e := range entries {
		_ = enc.Encode(e)
	}
}

// List returns the newest entries for one target (empty target = all).
func (a *auditTrail) List(target string, limit int) []AuditEntry {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	data, err := os.ReadFile(a.file())
	if err != nil {
		return []AuditEntry{}
	}
	var out []AuditEntry
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var e AuditEntry
		if json.Unmarshal([]byte(line), &e) != nil {
			continue
		}
		if target == "" || e.Target == target {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].At.After(out[j].At) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}
