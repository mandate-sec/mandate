package server

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"
)

func TestWorkspaceFileReplacement(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := root.WriteFile("original", []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := root.Link("original", "edited"); err != nil {
		t.Fatal(err)
	}
	broken := io.MultiReader(strings.NewReader("partial"), iotest.ErrReader(errors.New("input interrupted")))
	if err := replaceWorkspaceFile(root, "edited", broken); err == nil {
		t.Fatal("incomplete write succeeded")
	}
	if data, err := root.ReadFile("edited"); err != nil || string(data) != "old" {
		t.Fatal("failed write altered destination")
	}
	if err := replaceWorkspaceFile(root, "edited", strings.NewReader("new")); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"original": "old", "edited": "new"} {
		if data, err := root.ReadFile(name); err != nil || string(data) != want {
			t.Fatalf("%s: %q, %v", name, data, err)
		}
	}
	files, err := os.ReadDir(dir)
	if err != nil || len(files) != 2 {
		t.Fatal("temporary files remained", err)
	}
	for _, name := range []string{filepath.Join("..", "outside"), filepath.Join(dir, "absolute")} {
		if _, ok := workspacePath(name); ok {
			t.Fatalf("unexpected path accepted: %s", name)
		}
	}
}

func TestConsoleResponsePolicies(t *testing.T) {
	h := consoleBrowserHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	for _, path := range []string{"/", "/api/workspace/download"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		policy := w.Header().Get("Content-Security-Policy")
		if strings.Contains(policy, "img-src 'self' data: blob:") != (path == "/") {
			t.Fatalf("unexpected image policy for %s: %s", path, policy)
		}
		if !strings.Contains(policy, "frame-ancestors 'none'") || strings.Contains(policy, "sandbox") != strings.HasPrefix(path, "/api/") ||
			w.Header().Get("X-Content-Type-Options") != "nosniff" || w.Header().Get("Referrer-Policy") != "no-referrer" {
			t.Fatal(path, w.Header())
		}
	}
}
