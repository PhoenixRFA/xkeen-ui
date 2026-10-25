package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"xkeen-ui/internal/jobs"
	"xkeen-ui/internal/xkeen"
)

type xkeenState struct {
	mu  sync.Mutex
	ver string
}

const subLock = "/tmp/xray-sub-update.lock" // created by xray-sub-update while running

var viewable = map[string]string{
	"01_log": "01_log.json", "02_dns": "02_dns.json", "03_inbounds": "03_inbounds.json",
	"04_outbounds": "04_outbounds.json", "04_outbounds.main": "04_outbounds.main.json",
	"05_routing": "05_routing.json", "06_policy": "06_policy.json",
}

func (s *Server) xkeenRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/xkeen/status", s.xkeenStatus)
	for _, a := range []string{"start", "stop", "restart"} {
		a := a
		mux.HandleFunc("POST /api/xkeen/"+a, func(w http.ResponseWriter, r *http.Request) {
			s.startJob(w, "xkeen "+a, nil, func(ctx context.Context) (string, error) {
				return s.run(ctx, 2*time.Minute, nil, s.Cfg.Paths.InitScript, a)
			})
		})
	}
	mux.HandleFunc("POST /api/xkeen/test", s.xkeenTest)
	mux.HandleFunc("POST /api/subscription/update", s.subUpdate)
	mux.HandleFunc("GET /api/main-vpn", s.mainGet)
	mux.HandleFunc("PUT /api/main-vpn", s.mainPut)
	mux.HandleFunc("GET /api/files", s.filesList)
	mux.HandleFunc("GET /api/files/{name}", s.fileGet)
}

func (s *Server) startJob(w http.ResponseWriter, name string, extra map[string]any, fn func(context.Context) (string, error)) {
	id, err := s.Jobs.Start(name, fn)
	if errors.Is(err, jobs.ErrBusy) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "another job is running"})
		return
	}
	resp := map[string]any{"job": id}
	for k, v := range extra {
		resp[k] = v
	}
	writeJSON(w, http.StatusAccepted, resp)
}

// run executes a whitelisted command; a non-zero exit code becomes an error (output is still returned).
func (s *Server) run(ctx context.Context, d time.Duration, env []string, name string, args ...string) (string, error) {
	res, err := s.Exec.Run(ctx, d, env, name, args...)
	if err != nil {
		return res.Output, err
	}
	if res.Code != 0 {
		return res.Output, fmt.Errorf("exit code %d", res.Code)
	}
	return res.Output, nil
}

// xrayPID scans /proc for a process named "xray".
func xrayPID() (int, bool) {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return 0, false
	}
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if b, err := os.ReadFile("/proc/" + e.Name() + "/comm"); err == nil && strings.TrimSpace(string(b)) == "xray" {
			return pid, true
		}
	}
	return 0, false
}

func (s *Server) xrayVersion(ctx context.Context) string {
	s.xk.mu.Lock()
	defer s.xk.mu.Unlock()
	if s.xk.ver == "" {
		if res, err := s.Exec.Run(ctx, 10*time.Second, nil, s.Cfg.Checks.XrayBin, "version"); err == nil {
			s.xk.ver, _, _ = strings.Cut(strings.TrimSpace(res.Output), "\n")
		}
	}
	return s.xk.ver
}

func (s *Server) xkeenStatus(w http.ResponseWriter, r *http.Request) {
	p := s.Cfg.Paths
	pid, running := xrayPID()
	text := ""
	if res, err := s.Exec.Run(r.Context(), 10*time.Second, nil, p.InitScript, "status"); err != nil {
		text = err.Error()
	} else {
		text = strings.TrimSpace(res.Output)
	}
	stamp, msg := xkeen.LastSubAttempt(p.SubLog)
	changed := ""
	subFile := filepath.Join(p.XrayDir, "subscription.json")
	if fi, err := os.Stat(subFile); err == nil {
		changed = fi.ModTime().UTC().Format(time.RFC3339)
	}
	remarks, _ := xkeen.LoadRemarks(subFile)
	main, _ := s.mainState()
	writeJSON(w, http.StatusOK, map[string]any{
		"running": running, "pid": pid, "status_text": text,
		"xray_version": s.xrayVersion(r.Context()),
		"subscription": map[string]any{
			"last_check": stamp, "last_message": msg, "changed_at": changed, "entries": len(remarks),
		},
		"main": main,
	})
}

func (s *Server) xkeenTest(w http.ResponseWriter, r *http.Request) {
	dir := s.Cfg.Paths.XrayDir
	s.startJob(w, "xray test", nil, func(ctx context.Context) (string, error) {
		out, err := s.run(ctx, time.Minute, []string{"XRAY_LOCATION_ASSET=" + dir + "/dat"},
			s.Cfg.Checks.XrayBin, "run", "-test", "-confdir", dir+"/configs")
		return xkeen.FilterTest(out), err
	})
}

func (s *Server) logTail(n int) string {
	lines, _ := xkeen.TailLines(s.Cfg.Paths.SubLog, n)
	return strings.Join(lines, "\n")
}

func (s *Server) subUpdate(w http.ResponseWriter, r *http.Request) {
	if _, err := os.Stat(subLock); err == nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "subscription update is already running (cron?)"})
		return
	}
	s.startJob(w, "subscription update", nil, func(ctx context.Context) (string, error) {
		out, err := s.run(ctx, 3*time.Minute, nil, s.Cfg.Paths.SubUpdate)
		return strings.TrimSpace(out + "\n" + s.logTail(8)), err
	})
}

func (s *Server) mainState() (map[string]any, error) {
	dir := s.Cfg.Paths.XrayDir
	cur, err := xkeen.ReadMainRemark(filepath.Join(dir, "main-vpn.conf"))
	if err != nil {
		return nil, err
	}
	remarks, err := xkeen.LoadRemarks(filepath.Join(dir, "subscription.json"))
	if err != nil {
		return map[string]any{"remark": cur}, err
	}
	parts, eff := xkeen.Evaluate(cur, remarks)
	return map[string]any{"remark": cur, "parts": parts, "effective": eff, "remarks": remarks}, nil
}

func (s *Server) mainGet(w http.ResponseWriter, r *http.Request) {
	st, err := s.mainState()
	if err != nil && st == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) mainPut(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Remark string `json:"remark"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	if err := xkeen.ValidateMain(req.Remark); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	remarks, err := xkeen.LoadRemarks(filepath.Join(s.Cfg.Paths.XrayDir, "subscription.json"))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	parts, eff := xkeen.Evaluate(req.Remark, remarks)
	if eff == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no part matches exactly one subscription node"})
		return
	}
	var warns []string
	for _, p := range parts {
		if !p.OK {
			warns = append(warns, fmt.Sprintf("%q matches %d nodes and will be skipped", p.Text, p.Matches))
		}
	}
	s.startJob(w, "set main node", map[string]any{"warnings": warns, "effective": eff},
		func(ctx context.Context) (string, error) {
			out, err := s.run(ctx, 3*time.Minute, nil, s.Cfg.Paths.SetMain, req.Remark)
			return strings.TrimSpace(out + "\n" + s.logTail(8)), err
		})
}

func (s *Server) filesList(w http.ResponseWriter, r *http.Request) {
	names := make([]string, 0, len(viewable))
	for k := range viewable {
		names = append(names, k)
	}
	sort.Strings(names)
	writeJSON(w, http.StatusOK, map[string]any{"files": names})
}

func (s *Server) fileGet(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	fn, ok := viewable[name]
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown file"})
		return
	}
	path := filepath.Join(s.Cfg.Paths.XrayDir, "configs", fn)
	if fi, err := os.Stat(path); err != nil || fi.Size() > 256<<10 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "file not available"})
		return
	}
	b, err := os.ReadFile(path)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	masked := name == "04_outbounds.main" && r.URL.Query().Get("reveal") != "1"
	if masked {
		if mb, err := xkeen.MaskJSON(b); err == nil {
			b = mb
		} else {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "cannot mask file"})
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"name": name, "file": fn, "masked": masked, "content": string(b)})
}
