package server

import (
	"bytes"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"
)

// Workspace file manager — browse / view / edit / download / upload / delete the
// shared work dir (s.m.dir), where all agents write their artifacts. Every path is
// confined to the work dir root (traversal via ".." is neutralised). All routes sit
// behind requireAuth (see Handler()).

const (
	maxWorkspaceRead   = 2 << 20   // 2 MiB: files bigger than this aren't inlined for view/edit (download instead)
	maxWorkspaceUpload = 512 << 20 // 512 MiB per upload request
)

func (s *Server) workspaceRoot(w http.ResponseWriter) *os.Root {
	root, err := os.OpenRoot(s.m.dir)
	if err != nil {
		writeErr(w, 500, "Workspace unavailable")
		return nil
	}
	return root
}

type wsEntry struct {
	Name  string `json:"name"`
	Path  string `json:"path"`
	Dir   bool   `json:"dir"`
	Size  int64  `json:"size"`
	MTime int64  `json:"mtime"` // unix millis
}

// GET /api/workspace/list?path=<rel>
func (s *Server) wsList(w http.ResponseWriter, r *http.Request) {
	root := s.workspaceRoot(w)
	if root == nil {
		return
	}
	defer root.Close()
	name, ok := workspacePath(r.URL.Query().Get("path"))
	if !ok {
		writeErr(w, 400, "非法路径")
		return
	}
	fi, err := root.Stat(name)
	if err != nil {
		writeErr(w, 404, "路径不存在")
		return
	}
	if !fi.IsDir() {
		writeErr(w, 400, "不是目录")
		return
	}
	ents, err := fs.ReadDir(root.FS(), filepath.ToSlash(name))
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	out := make([]wsEntry, 0, len(ents))
	for _, e := range ents {
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, wsEntry{
			Name:  e.Name(),
			Path:  workspaceDisplay(filepath.Join(name, e.Name())),
			Dir:   e.IsDir(),
			Size:  info.Size(),
			MTime: info.ModTime().UnixMilli(),
		})
	}
	// 目录在前，各自按名称排序。
	sort.Slice(out, func(i, j int) bool {
		if out[i].Dir != out[j].Dir {
			return out[i].Dir
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	writeJSON(w, 200, map[string]any{"path": workspaceDisplay(name), "entries": out})
}

// GET /api/workspace/read?path=<rel> — inline text for view/edit. Binary or oversize
// files return {binary:true}/{too_large:true} with no content (use download instead).
func (s *Server) wsRead(w http.ResponseWriter, r *http.Request) {
	root := s.workspaceRoot(w)
	if root == nil {
		return
	}
	defer root.Close()
	name, ok := workspacePath(r.URL.Query().Get("path"))
	if !ok {
		writeErr(w, 400, "非法路径")
		return
	}
	fi, err := root.Stat(name)
	if err != nil {
		writeErr(w, 404, "文件不存在")
		return
	}
	if !fi.Mode().IsRegular() {
		writeErr(w, 400, "Expected a regular file")
		return
	}
	if fi.Size() > maxWorkspaceRead {
		writeJSON(w, 200, map[string]any{"path": workspaceDisplay(name), "size": fi.Size(), "too_large": true, "binary": true})
		return
	}
	file, err := root.Open(name)
	if err != nil {
		writeErr(w, 404, "File unavailable")
		return
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxWorkspaceRead+1))
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if len(data) > maxWorkspaceRead {
		writeJSON(w, 200, map[string]any{"path": workspaceDisplay(name), "size": len(data), "too_large": true, "binary": true})
		return
	}
	if bytes.IndexByte(data, 0) >= 0 || !utf8.Valid(data) {
		writeJSON(w, 200, map[string]any{"path": workspaceDisplay(name), "size": fi.Size(), "binary": true})
		return
	}
	writeJSON(w, 200, map[string]any{"path": workspaceDisplay(name), "size": fi.Size(), "binary": false, "content": string(data)})
}

// POST /api/workspace/write  {path, content} — create/overwrite a text file.
func (s *Server) wsWrite(w http.ResponseWriter, r *http.Request) {
	root := s.workspaceRoot(w)
	if root == nil {
		return
	}
	defer root.Close()
	r.Body = http.MaxBytesReader(w, r.Body, 6*maxWorkspaceRead+8192)
	var req struct {
		Path    string `json:"path"`
		Content string `json:"content"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if len(req.Content) > maxWorkspaceRead {
		writeErr(w, 413, "File exceeds editor size limit")
		return
	}
	name, ok := workspacePath(req.Path)
	if !ok || name == "." {
		writeErr(w, 400, "非法路径")
		return
	}
	if fi, err := root.Stat(name); err == nil && fi.IsDir() {
		writeErr(w, 400, "目标是目录")
		return
	}
	if err := root.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if err := replaceWorkspaceFile(root, name, strings.NewReader(req.Content)); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "path": workspaceDisplay(name)})
}

// POST /api/workspace/mkdir  {path}
func (s *Server) wsMkdir(w http.ResponseWriter, r *http.Request) {
	root := s.workspaceRoot(w)
	if root == nil {
		return
	}
	defer root.Close()
	var req struct {
		Path string `json:"path"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	name, ok := workspacePath(req.Path)
	if !ok || name == "." {
		writeErr(w, 400, "非法路径")
		return
	}
	if err := root.MkdirAll(name, 0o755); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "path": workspaceDisplay(name)})
}

// DELETE /api/workspace/delete?path=<rel> — removes a file or a directory tree
// (confined to the work dir; the root itself can't be deleted).
func (s *Server) wsDelete(w http.ResponseWriter, r *http.Request) {
	root := s.workspaceRoot(w)
	if root == nil {
		return
	}
	defer root.Close()
	name, ok := workspacePath(r.URL.Query().Get("path"))
	if !ok {
		writeErr(w, 400, "非法路径")
		return
	}
	if name == "." {
		writeErr(w, 400, "不能删除工作区根目录")
		return
	}
	if _, err := root.Lstat(name); err != nil {
		writeErr(w, 404, "路径不存在")
		return
	}
	if err := root.RemoveAll(name); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// GET /api/workspace/download?path=<rel> — stream a file as an attachment.
func (s *Server) wsDownload(w http.ResponseWriter, r *http.Request) {
	root := s.workspaceRoot(w)
	if root == nil {
		return
	}
	defer root.Close()
	name, ok := workspacePath(r.URL.Query().Get("path"))
	if !ok {
		writeErr(w, 400, "非法路径")
		return
	}
	fi, err := root.Stat(name)
	if err != nil || !fi.Mode().IsRegular() {
		writeErr(w, 404, "File unavailable")
		return
	}
	file, err := root.Open(name)
	if err != nil {
		writeErr(w, 404, "File unavailable")
		return
	}
	defer file.Close()
	fi, err = file.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		writeErr(w, 404, "File unavailable")
		return
	}
	name = filepath.Base(name)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": name}))
	http.ServeContent(w, r, name, fi.ModTime(), file)
}

// POST /api/workspace/upload?path=<dir> — multipart form field "file" (one or more).
func (s *Server) wsUpload(w http.ResponseWriter, r *http.Request) {
	root := s.workspaceRoot(w)
	if root == nil {
		return
	}
	defer root.Close()
	dirName, ok := workspacePath(r.URL.Query().Get("path"))
	if !ok {
		writeErr(w, 400, "非法路径")
		return
	}
	if fi, err := root.Stat(dirName); err != nil || !fi.IsDir() {
		writeErr(w, 400, "目标目录不存在")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxWorkspaceUpload)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeErr(w, 400, "解析上传失败或超出大小限制："+err.Error())
		return
	}
	files := r.MultipartForm.File["file"]
	if len(files) == 0 {
		writeErr(w, 400, "缺少上传文件(表单字段 file)")
		return
	}
	saved := 0
	for _, hdr := range files {
		name := filepath.Base(hdr.Filename) // strip any path component
		if name == "" || name == "." || name == ".." {
			continue
		}
		dest, okd := workspacePath(filepath.Join(workspaceDisplay(dirName), name))
		if !okd {
			continue
		}
		if err := saveUpload(root, hdr, dest, os.O_TRUNC); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		saved++
	}
	writeJSON(w, 200, map[string]any{"uploaded": saved})
}
