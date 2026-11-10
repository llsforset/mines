package web

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/bishopfox/sliver/server/assets"
	"github.com/bishopfox/sliver/server/log"
)

var filesLog = log.NamedLogger("web", "files")

// FileRecord is one file pulled back from a target and archived server-side
// so the console can preview it again later.
type FileRecord struct {
	ID         string    `json:"ID"`
	Target     string    `json:"Target"` // lite:<id> / session:<id> / beacon:<id>
	SourcePath string    `json:"SourcePath"`
	Name       string    `json:"Name"`
	Size       int       `json:"Size"`
	At         time.Time `json:"At"`
}

type fileStore struct {
	mutex   sync.Mutex
	dir     string
	records []FileRecord
	loaded  bool
}

// grabbedFiles archives every completed download (C via OnCompletedFile,
// Go via the download handler).
var grabbedFiles = &fileStore{}

func baseName(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[i+1:]
	}
	return p
}

func (f *fileStore) root() string {
	if f.dir == "" {
		f.dir = filepath.Join(assets.GetRootAppDir(), "files")
	}
	return f.dir
}

func (f *fileStore) loadLocked() {
	if f.loaded {
		return
	}
	f.loaded = true
	data, err := os.ReadFile(filepath.Join(f.root(), "index.json"))
	if err != nil {
		return
	}
	_ = json.Unmarshal(data, &f.records)
}

func (f *fileStore) persistLocked() {
	data, err := json.Marshal(f.records)
	if err != nil {
		return
	}
	_ = os.MkdirAll(f.root(), 0o700)
	_ = os.WriteFile(filepath.Join(f.root(), "index.json"), data, 0o600)
}

// Save stores the bytes and records the metadata. A random ID keys the blob
// on disk; the source path is only metadata, never used to place the file.
func (f *fileStore) Save(target, sourcePath string, data []byte) (FileRecord, error) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.loadLocked()
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return FileRecord{}, err
	}
	rec := FileRecord{
		ID:         hex.EncodeToString(buf),
		Target:     target,
		SourcePath: sourcePath,
		Name:       baseName(sourcePath),
		Size:       len(data),
		At:         time.Now(),
	}
	if err := os.MkdirAll(filepath.Join(f.root(), "data"), 0o700); err != nil {
		return rec, err
	}
	if err := os.WriteFile(filepath.Join(f.root(), "data", rec.ID), data, 0o600); err != nil {
		return rec, err
	}
	f.records = append(f.records, rec)
	f.persistLocked()
	return rec, nil
}

// List returns records for one target, newest first; empty target lists all.
func (f *fileStore) List(target string) []FileRecord {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.loadLocked()
	out := make([]FileRecord, 0, len(f.records))
	for _, rec := range f.records {
		if target == "" || rec.Target == target {
			out = append(out, rec)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].At.After(out[j].At) })
	return out
}

var errNoFileRecord = errors.New("没有这条文件记录")

func (f *fileStore) Get(id string) (FileRecord, []byte, error) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.loadLocked()
	for _, rec := range f.records {
		if rec.ID == id {
			data, err := os.ReadFile(filepath.Join(f.root(), "data", id))
			if err != nil {
				return rec, nil, err
			}
			return rec, data, nil
		}
	}
	return FileRecord{}, nil, errNoFileRecord
}

func (f *fileStore) Delete(id string) error {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.loadLocked()
	found := false
	out := f.records[:0]
	for _, rec := range f.records {
		if rec.ID == id {
			found = true
			continue
		}
		out = append(out, rec)
	}
	if !found {
		return errNoFileRecord
	}
	f.records = out
	_ = os.Remove(filepath.Join(f.root(), "data", id))
	f.persistLocked()
	return nil
}

// previewContentType gives the browser a useful Content-Type for inline
// preview; unknown types stay octet-stream so the browser never guesses HTML.
func previewContentType(name string) string {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".json", ".map":
		return "application/json"
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".gif":
		return "image/gif"
	case ".webp":
		return "image/webp"
	case ".bmp":
		return "image/bmp"
	case ".svg":
		return "image/svg+xml"
	case ".ico":
		return "image/x-icon"
	case ".pdf":
		return "application/pdf"
	case ".mp4", ".m4v":
		return "video/mp4"
	case ".webm":
		return "video/webm"
	case ".mp3":
		return "audio/mpeg"
	case ".wav":
		return "audio/wav"
	default:
		return "text/plain; charset=utf-8"
	}
}
