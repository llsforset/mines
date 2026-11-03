package litebeacon

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/bishopfox/sliver/server/assets"
)

// Business paths only. Names that describe the channel are rejected so a
// generated URL does not label itself.
var reservedPathWords = []string{"lite", "beacon", "sliver", "implant", "c2", "callback", "malware"}

var (
	pathMutex sync.Mutex
	pathFile  string
	pathSet   = map[string]struct{}{}
	pathsLoad bool
)

func pathsPath() string {
	return filepath.Join(assets.GetRootAppDir(), "litebeacon", "paths.json")
}

func loadPaths() error {
	pathMutex.Lock()
	defer pathMutex.Unlock()
	return loadPathsLocked()
}

func loadPathsLocked() error {
	file := pathsPath()
	if pathsLoad && pathFile == file {
		return nil
	}
	pathFile = file
	pathSet = map[string]struct{}{}
	data, err := os.ReadFile(file)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err == nil && len(data) > 0 {
		var list []string
		if err := json.Unmarshal(data, &list); err != nil {
			return err
		}
		for _, item := range list {
			if item != "" {
				pathSet[item] = struct{}{}
			}
		}
	}
	pathsLoad = true
	return nil
}

// NormalizePath checks that a check-in path looks like an ordinary route.
func NormalizePath(raw string) (string, error) {
	path := strings.TrimSpace(raw)
	if path == "" {
		path = DefaultPath
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if strings.Contains(path, "..") || strings.Contains(path, "\\") || strings.Contains(path, "?") {
		return "", errBadPath
	}
	if len(path) > 200 {
		return "", errBadPath
	}
	lower := strings.ToLower(path)
	for _, word := range reservedPathWords {
		if strings.Contains(lower, word) {
			return "", errBadPath
		}
	}
	return path, nil
}

var errBadPath = errString("路径要像普通业务接口，不能包含空格、..，也不能写出通道本身")

type errString string

func (e errString) Error() string { return string(e) }

// RegisterPath remembers a check-in path so the shared HTTPS listener can
// hand that route to the C implant handler.
func RegisterPath(raw string) (string, error) {
	path, err := NormalizePath(raw)
	if err != nil {
		return "", err
	}
	pathMutex.Lock()
	defer pathMutex.Unlock()
	if err := loadPathsLocked(); err != nil {
		return "", err
	}
	pathSet[path] = struct{}{}
	if err := savePathsLocked(); err != nil {
		delete(pathSet, path)
		return "", err
	}
	return path, nil
}

func knownPath(path string) bool {
	pathMutex.Lock()
	defer pathMutex.Unlock()
	if err := loadPathsLocked(); err != nil {
		return false
	}
	_, ok := pathSet[path]
	return ok
}

func savePathsLocked() error {
	list := make([]string, 0, len(pathSet))
	for path := range pathSet {
		list = append(list, path)
	}
	if err := os.MkdirAll(filepath.Dir(pathFile), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(pathFile, data, 0o600)
}
