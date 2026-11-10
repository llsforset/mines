package litebeacon

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestImplantSourcesHideKeyCtx(t *testing.T) {
	dir := filepath.Join("..", "..", "implant", "lite")
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	needle := []byte(keyCtx)
	for _, ent := range ents {
		if ent.IsDir() {
			continue
		}
		name := ent.Name()
		switch filepath.Ext(name) {
		case ".c", ".h":
		default:
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, needle) {
			t.Errorf("%s contains plaintext key context", name)
		}
	}
}
