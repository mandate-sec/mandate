// Package journal publishes recovery plans before their first filesystem mutation.
package journal

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
)

// Create links a complete, synced JSON document into place without replacing a prior plan.
func Create(dataDir, path string, value any) error {
	rel, err := filepath.Rel(dataDir, path)
	if err != nil {
		return err
	}
	if !filepath.IsLocal(rel) || rel == "." {
		return errors.New("invalid recovery journal path")
	}
	root, err := os.OpenRoot(dataDir)
	if err != nil {
		return err
	}
	defer root.Close()
	parent, err := root.OpenRoot(filepath.Dir(rel))
	if err != nil {
		return err
	}
	defer parent.Close()
	tmp := ".journal-" + rand.Text()
	file, err := parent.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer parent.Remove(tmp)
	err = json.NewEncoder(file).Encode(value)
	if err == nil {
		err = file.Sync()
	}
	if err = errors.Join(err, file.Close()); err != nil {
		return err
	}
	if err = parent.Link(tmp, filepath.Base(rel)); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		dir, err := parent.Open(".")
		if err != nil {
			return err
		}
		defer dir.Close()
		return dir.Sync()
	}
	return nil
}
