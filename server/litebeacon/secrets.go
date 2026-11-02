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
	KeyName   string    `json:"key"`
	CreatedAt time.Time `json:"created"`
	Label     string    `json:"label"`
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
	before := len(r.entries)
	r.entries = append(r.entries, entry)
	if err := r.save(); err != nil {
		r.entries = r.entries[:before] // 落盘失败回滚，避免内存里残留未持久化的幽灵密钥
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
