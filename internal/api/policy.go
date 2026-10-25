package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"xkeen-ui/internal/policy"
)

type policyState struct {
	mu    sync.Mutex // serializes router writes
	dirty atomic.Bool // running config changed since the last Save
}

var rciClient = &http.Client{Timeout: 5 * time.Second}

func (s *Server) policyRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/clients", s.clientsGet)
	mux.HandleFunc("PUT /api/clients/{mac}/policy", s.clientPolicySet)
	mux.HandleFunc("POST /api/system/save", s.systemSave)
}

func (s *Server) rciGet(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(s.Cfg.Paths.RCIURL, "/")+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := rciClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("RCI %s: %s", path, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 4<<20))
}

func (s *Server) loadPolicies(ctx context.Context) ([]policy.Policy, error) {
	b, err := s.rciGet(ctx, "/rci/show/ip/policy")
	if err != nil {
		return nil, err
	}
	return policy.ParsePolicies(b, s.Cfg.Policies.Highlight)
}

func (s *Server) loadClients(ctx context.Context) ([]policy.Client, error) {
	b, err := s.rciGet(ctx, "/rci/show/ip/hotspot")
	if err != nil {
		return nil, err
	}
	return policy.ParseHosts(b)
}

func fail(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func (s *Server) clientsGet(w http.ResponseWriter, r *http.Request) {
	pols, err := s.loadPolicies(r.Context())
	if err != nil {
		fail(w, http.StatusBadGateway, err.Error())
		return
	}
	cls, err := s.loadClients(r.Context())
	if err != nil {
		fail(w, http.StatusBadGateway, err.Error())
		return
	}
	sort.Slice(cls, func(i, j int) bool {
		if cls[i].Online != cls[j].Online {
			return cls[i].Online
		}
		return strings.ToLower(cls[i].Name) < strings.ToLower(cls[j].Name)
	})
	writeJSON(w, http.StatusOK, map[string]any{"policies": pols, "clients": cls, "unsaved": s.pol.dirty.Load()})
}

func (s *Server) clientPolicySet(w http.ResponseWriter, r *http.Request) {
	mac, ok := policy.NormMAC(r.PathValue("mac"))
	if !ok {
		fail(w, http.StatusBadRequest, "invalid MAC")
		return
	}
	var req struct {
		Policy *string `json:"policy"` // null or "" = Default (no policy)
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&req); err != nil {
		fail(w, http.StatusBadRequest, "bad request")
		return
	}
	want := ""
	if req.Policy != nil {
		want = *req.Policy
	}
	s.pol.mu.Lock()
	defer s.pol.mu.Unlock()

	if want != "" {
		pols, err := s.loadPolicies(r.Context())
		if err != nil {
			fail(w, http.StatusBadGateway, err.Error())
			return
		}
		found := false
		for _, p := range pols {
			found = found || p.ID == want
		}
		if !found {
			fail(w, http.StatusBadRequest, "unknown policy")
			return
		}
	}
	if !s.clientHas(r.Context(), mac, nil) {
		fail(w, http.StatusNotFound, "client not found")
		return
	}
	res, err := s.Exec.Run(r.Context(), 15*time.Second, nil, s.Cfg.Paths.Ndmc, "-c", policy.SetCommand(mac, want))
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !s.clientHas(r.Context(), mac, &want) { // do not trust the exit code alone
		fail(w, http.StatusInternalServerError, "router did not apply the change: "+strings.TrimSpace(res.Output))
		return
	}
	s.pol.dirty.Store(true)
	writeJSON(w, http.StatusOK, map[string]any{"mac": mac, "policy": want, "unsaved": true})
}

// clientHas reports whether the client exists and, if policy != nil, has exactly that policy.
func (s *Server) clientHas(ctx context.Context, mac string, policy *string) bool {
	cls, err := s.loadClients(ctx)
	if err != nil {
		return false
	}
	for _, c := range cls {
		if c.MAC == mac {
			return policy == nil || c.Policy == *policy
		}
	}
	return false
}

func (s *Server) systemSave(w http.ResponseWriter, r *http.Request) {
	s.pol.mu.Lock()
	defer s.pol.mu.Unlock()
	res, err := s.Exec.Run(r.Context(), 30*time.Second, nil, s.Cfg.Paths.Ndmc, "-c", "system configuration save")
	if err != nil || res.Code != 0 {
		msg := strings.TrimSpace(res.Output)
		if err != nil {
			msg = err.Error()
		}
		fail(w, http.StatusInternalServerError, "save failed: "+msg)
		return
	}
	s.pol.dirty.Store(false)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "output": strings.TrimSpace(res.Output)})
}
