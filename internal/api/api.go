// Package api: HTTP server, access control, session auth.
package api

import (
	"encoding/json"
	"net"
	"net/http"
	"time"

	"xkeen-ui/internal/auth"
	"xkeen-ui/internal/config"
	"xkeen-ui/internal/execx"
	"xkeen-ui/internal/jobs"
	"xkeen-ui/web"
)

const cookieName = "xkui"

type Server struct {
	CfgPath  string
	Cfg      *config.Config
	Version  string
	Sessions *auth.Sessions
	Limiter  *auth.Limiter
	Jobs     *jobs.Manager
	Exec     *execx.Runner
	nets     []*net.IPNet
	xk       xkeenState
}

func New(cfgPath string, cfg *config.Config, version string) (*Server, error) {
	s := &Server{
		CfgPath:  cfgPath,
		Cfg:      cfg,
		Version:  version,
		Sessions: auth.NewSessions(time.Duration(cfg.SessionTTLHours) * time.Hour),
		Limiter:  auth.NewLimiter(),
		Jobs:     jobs.New(),
		Exec: execx.New(cfg.Paths.InitScript, cfg.Paths.SubUpdate, cfg.Paths.SetMain, cfg.Checks.XrayBin),
	}
	for _, c := range cfg.AllowCIDRs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			return nil, err
		}
		s.nets = append(s.nets, n)
	}
	return s, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/login", s.login)
	mux.HandleFunc("POST /api/logout", s.logout)
	mux.HandleFunc("GET /api/version", s.version)
	mux.HandleFunc("GET /api/me", s.me)
	mux.HandleFunc("GET /api/jobs/{id}", s.job)
	s.xkeenRoutes(mux)
	mux.Handle("/", http.FileServer(http.FS(web.FS)))
	return s.secure(s.guard(mux))
}

func clientIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

// secure: LAN allow-list and security headers.
func (s *Server) secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := net.ParseIP(clientIP(r))
		ok := len(s.nets) == 0
		for _, n := range s.nets {
			if ip != nil && n.Contains(ip) {
				ok = true
			}
		}
		if !ok {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		h := w.Header()
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy",
			"default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

// guard: /api/* needs a session (except login/version); writes need the CSRF header.
func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.URL.Path) >= 5 && r.URL.Path[:5] == "/api/" {
			w.Header().Set("Cache-Control", "no-store")
			if r.Method != http.MethodGet && r.Header.Get("X-Requested-With") != "xkeen-ui" {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "missing header"})
				return
			}
			public := r.URL.Path == "/api/login" || r.URL.Path == "/api/version"
			if !public {
				c, err := r.Cookie(cookieName)
				if err != nil || !s.Sessions.Valid(c.Value) {
					writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if s.Limiter.Blocked(ip) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many attempts, try later"})
		return
	}
	var req struct{ User, Password string }
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	cfg := s.Cfg
	if fresh, err := config.Load(s.CfgPath); err == nil { // picks up `xkeen-ui passwd` without restart
		cfg = fresh
	}
	if !auth.Verify(cfg.Auth, req.User, req.Password) {
		s.Limiter.Fail(ip)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}
	s.Limiter.Reset(ip)
	tok, err := s.Sessions.New()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "session error"})
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: tok, Path: "/", HttpOnly: true,
		SameSite: http.SameSiteStrictMode, MaxAge: cfg.SessionTTLHours * 3600,
	})
	writeJSON(w, http.StatusOK, map[string]string{"user": cfg.Auth.User})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		s.Sessions.Delete(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Path: "/", MaxAge: -1})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) version(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"version": s.Version})
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"user": s.Cfg.Auth.User})
}

func (s *Server) job(w http.ResponseWriter, r *http.Request) {
	j, ok := s.Jobs.Get(r.PathValue("id"))
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such job"})
		return
	}
	writeJSON(w, http.StatusOK, j)
}
