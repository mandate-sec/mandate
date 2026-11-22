package server

import (
	"crypto/rand"
	"io"
	"mime/multipart"
	"os"
	"path/filepath"
)

// workspacePath accepts relative paths and uses "." for the workspace root.
func workspacePath(name string) (string, bool) {
	if name == "" {
		return ".", true
	}
	name = filepath.FromSlash(name)
	if !filepath.IsLocal(name) {
		return "", false
	}
	return filepath.Clean(name), true
}

func workspaceDisplay(name string) string {
	if name == "." {
		return ""
	}
	return filepath.ToSlash(name)
}

func saveUpload(root *os.Root, hdr *multipart.FileHeader, dest string, mode int) error {
	src, err := hdr.Open()
	if err != nil {
		return err
	}
	defer src.Close()
	if mode == os.O_TRUNC {
		return replaceWorkspaceFile(root, dest, src)
	}
	out, err := root.OpenFile(dest, os.O_WRONLY|os.O_CREATE|mode, 0600)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, src)
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

// Replace the directory entry only after a complete write. Existing hard links
// and symbolic links are replaced without modifying their targets.
func replaceWorkspaceFile(root *os.Root, dest string, src io.Reader) error {
	temp := filepath.Join(filepath.Dir(dest), ".upload-"+rand.Text())
	f, err := root.OpenFile(temp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer root.Remove(temp)
	_, copyErr := io.Copy(f, src)
	closeErr := f.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	return root.Rename(temp, dest)
}
