package api

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"xkeen-ui/internal/xkeen"
)

const subBackupPrefix = "sub.curl."

func (s *Server) subCurlRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/sub-curl", s.subCurlGet)
	mux.HandleFunc("PUT /api/sub-curl", s.subCurlPut)
	mux.HandleFunc("GET /api/sub-curl/backups", s.subCurlBackups)
	mux.HandleFunc("GET /api/sub-curl/backups/{name}", s.subCurlBackupGet)
}

func (s *Server) subCurlPath() string { return filepath.Join(s.Cfg.Paths.XrayDir, "sub.curl") }

func (s *Server) subCurlGet(w http.ResponseWriter, r *http.Request) {
	b, err := os.ReadFile(s.subCurlPath())
	if os.IsNotExist(err) {
		writeJSON(w, http.StatusOK, map[string]any{"content": "", "exists": false})
		return
	}
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	mt := ""
	if fi, err := os.Stat(s.subCurlPath()); err == nil {
		mt = fi.ModTime().UTC().Format(time.RFC3339)
	}
	writeJSON(w, http.StatusOK, map[string]any{"content": string(b), "exists": true, "mod_time": mt})
}

func (s *Server) subCurlPut(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Content string `json:"content"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		fail(w, http.StatusBadRequest, "bad request")
		return
	}
	content, err := xkeen.ValidateSubCurl(req.Content)
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	s.pol.mu.Lock() // reuse: serialize config-file writes with router writes
	defer s.pol.mu.Unlock()
	name, err := xkeen.Backup(s.subCurlPath(), s.Cfg.Paths.BackupDir, subBackupPrefix, s.Cfg.BackupKeep)
	if err != nil {
		fail(w, http.StatusInternalServerError, "backup failed, file not changed: "+err.Error())
		return
	}
	if err := xkeen.WriteAtomic(s.subCurlPath(), []byte(content), 0o600); err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "backup": name})
}

func (s *Server) subCurlBackups(w http.ResponseWriter, r *http.Request) {
	list, err := xkeen.ListBackups(s.Cfg.Paths.BackupDir, subBackupPrefix)
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	if list == nil {
		list = []xkeen.BackupInfo{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"backups": list})
}

func (s *Server) subCurlBackupGet(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !xkeen.ValidBackupName(name, subBackupPrefix) {
		fail(w, http.StatusBadRequest, "invalid backup name")
		return
	}
	b, err := os.ReadFile(filepath.Join(s.Cfg.Paths.BackupDir, name))
	if err != nil {
		fail(w, http.StatusNotFound, "backup not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"name": name, "content": string(b)})
}
