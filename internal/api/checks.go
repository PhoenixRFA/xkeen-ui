package api

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"xkeen-ui/internal/checks"
	"xkeen-ui/internal/xkeen"
)

type checkState struct{ mu sync.Mutex } // one tunnel check at a time

var nodeRe = regexp.MustCompile(`^(main-vpn|yt-\d+)$`)

func (s *Server) checkRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/logs/{name}", s.logsGet)
	mux.HandleFunc("POST /api/check/router", s.routerCheck)
	mux.HandleFunc("POST /api/check/site", s.siteCheck)
	mux.HandleFunc("GET /api/check/nodes", s.nodesGet)
	mux.HandleFunc("POST /api/check/tunnel", s.tunnelCheck)
}

// ---- logs ----

func (s *Server) logsGet(w http.ResponseWriter, r *http.Request) {
	n := s.Cfg.LogTailLines
	if v, err := strconv.Atoi(r.URL.Query().Get("n")); err == nil && v > 0 {
		n = min(v, 2000)
	}
	var lines []string
	var err error
	switch name := r.PathValue("name"); name {
	case "error":
		lines, err = xkeen.TailLines(s.Cfg.Paths.ErrorLog, n)
	case "sub":
		lines, err = xkeen.TailLines(s.Cfg.Paths.SubLog, n)
	case "router":
		var res string
		res, err = s.run(r.Context(), 20*time.Second, nil, s.Cfg.Paths.Ndmc, "-c", "show log")
		lines = strings.Split(strings.TrimRight(res, "\n"), "\n")
		if len(lines) > n {
			lines = lines[len(lines)-n:]
		}
	default:
		fail(w, http.StatusNotFound, "unknown log")
		return
	}
	if os.IsNotExist(err) {
		writeJSON(w, http.StatusOK, map[string]any{"content": "(file does not exist yet)"})
		return
	}
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"content": strings.Join(lines, "\n")})
}

// ---- router check: ping + DNS + direct IP ----

func (s *Server) nslookup(ctx context.Context, domain string) (ip string, ms int64, out string, ok bool) {
	t0 := time.Now()
	res, _ := s.Exec.Run(ctx, 8*time.Second, nil, "nslookup", domain, s.Cfg.DNSServer)
	ip, ok = checks.ParseNslookup(res.Output)
	return ip, time.Since(t0).Milliseconds(), strings.TrimSpace(res.Output), ok
}

func (s *Server) routerCheck(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	c := s.Cfg.Checks
	var wg sync.WaitGroup
	var ping, dns map[string]any
	var direct checks.EchoResult
	wg.Add(3)
	go func() {
		defer wg.Done()
		res, err := s.Exec.Run(ctx, 15*time.Second, nil, "ping", "-c", "3", "-W", "2", c.PingTarget)
		p := checks.ParsePing(res.Output)
		ping = map[string]any{"target": c.PingTarget, "ok": p.Recv > 0, "loss_pct": p.LossPct, "avg_ms": p.AvgMs, "min_ms": p.MinMs, "max_ms": p.MaxMs}
		if err != nil {
			ping["error"] = err.Error()
		}
	}()
	go func() {
		defer wg.Done()
		ip, ms, _, ok := s.nslookup(ctx, c.RouterDNSProbe)
		dns = map[string]any{"probe": c.RouterDNSProbe, "server": s.Cfg.DNSServer, "ok": ok, "ip": ip, "ms": ms}
	}()
	go func() {
		defer wg.Done()
		cl := checks.DirectClient(s.Cfg.DNSServer)
		defer cl.CloseIdleConnections()
		direct = checks.IPEcho(ctx, cl, c.IPEchoURLs, c.IPEchoRequests)
	}()
	wg.Wait()
	writeJSON(w, http.StatusOK, map[string]any{"ping": ping, "dns": dns, "direct": direct})
}

// ---- site check: DNS + ipset ----

func (s *Server) siteCheck(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&req); err != nil {
		fail(w, http.StatusBadRequest, "bad request")
		return
	}
	domain, err := checks.CleanDomain(req.Domain)
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	ip, _, dnsOut, ok := s.nslookup(ctx, domain)
	resp := map[string]any{"domain": domain, "dns_output": dnsOut}
	if !ok {
		resp["verdict"] = "unresolved"
		writeJSON(w, http.StatusOK, resp)
		return
	}
	resp["ip"] = ip
	res, err := s.Exec.Run(ctx, 8*time.Second, nil, "ipset", "test", s.Cfg.Checks.IPSetName, ip)
	resp["ipset_output"] = strings.TrimSpace(res.Output)
	switch {
	case err != nil:
		resp["verdict"], resp["error"] = "unknown", err.Error()
	case res.Code == 0:
		resp["verdict"] = "direct" // in geo_exclude: bypasses the tunnel
	case res.Code == 1:
		resp["verdict"] = "tunnel"
	default:
		resp["verdict"] = "unknown"
	}
	resp["set"] = s.Cfg.Checks.IPSetName
	writeJSON(w, http.StatusOK, resp)
}

// ---- tunnel check: temporary xray + IP echo through it ----

func (s *Server) outbounds() (map[string]json.RawMessage, []string, error) {
	b, err := os.ReadFile(filepath.Join(s.Cfg.Paths.XrayDir, "configs", "04_outbounds.main.json"))
	if err != nil {
		return nil, nil, err
	}
	var doc struct {
		Outbounds []json.RawMessage `json:"outbounds"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, nil, err
	}
	m := map[string]json.RawMessage{}
	var tags []string
	for _, raw := range doc.Outbounds {
		var t struct {
			Tag string `json:"tag"`
		}
		if json.Unmarshal(raw, &t) == nil && nodeRe.MatchString(t.Tag) {
			m[t.Tag] = raw
			tags = append(tags, t.Tag)
		}
	}
	return m, tags, nil
}

func (s *Server) nodesGet(w http.ResponseWriter, r *http.Request) {
	_, tags, err := s.outbounds()
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"nodes": tags})
}

func freePort(pref int) int {
	if pref > 0 {
		if l, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(pref)); err == nil {
			l.Close()
			return pref
		}
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func waitPort(addr string, done <-chan struct{}, d time.Duration) bool {
	for deadline := time.Now().Add(d); time.Now().Before(deadline); time.Sleep(150 * time.Millisecond) {
		select {
		case <-done:
			return false
		default:
		}
		if c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond); err == nil {
			c.Close()
			return true
		}
	}
	return false
}

func tail(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		s = "…" + s[len(s)-n:]
	}
	return s
}

func (s *Server) tunnelCheck(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Node string `json:"node"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&req); err != nil || !nodeRe.MatchString(req.Node) {
		fail(w, http.StatusBadRequest, "invalid node")
		return
	}
	if !s.chk.mu.TryLock() {
		fail(w, http.StatusConflict, "another tunnel check is running")
		return
	}
	defer s.chk.mu.Unlock()

	nodes, _, err := s.outbounds()
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	ob, ok := nodes[req.Node]
	if !ok {
		fail(w, http.StatusNotFound, "node not found in 04_outbounds.main.json")
		return
	}
	dir, err := os.MkdirTemp("", "xkeen-ui-check-")
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer os.RemoveAll(dir)
	port := freePort(s.Cfg.Checks.TunnelCheckPort)
	if port == 0 {
		fail(w, http.StatusInternalServerError, "no free local port")
		return
	}
	cfg, _ := json.Marshal(map[string]any{
		"log":       map[string]string{"loglevel": "warning"},
		"inbounds":  []any{map[string]any{"tag": "ui-check", "protocol": "http", "listen": "127.0.0.1", "port": port}},
		"outbounds": []json.RawMessage{ob}, // single outbound, no routing: everything goes through it
	})
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, cfg, 0o600); err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	resp := map[string]any{"node": req.Node}
	proc, err := s.Exec.Start(nil, s.Cfg.Checks.XrayBin, "run", "-c", cfgPath)
	if err != nil {
		resp["ok"], resp["error"] = false, "cannot start xray: "+err.Error()
		writeJSON(w, http.StatusOK, resp)
		return
	}
	var xrayLog string
	defer func() { proc.Stop() }()

	if !waitPort("127.0.0.1:"+strconv.Itoa(port), proc.Done(), 8*time.Second) {
		xrayLog = proc.Stop()
		resp["ok"], resp["error"], resp["xray_log"] = false, "temporary xray did not start", tail(xrayLog, 1500)
		writeJSON(w, http.StatusOK, resp)
		return
	}
	pu, _ := url.Parse("http://127.0.0.1:" + strconv.Itoa(port))
	tc := checks.ProxyClient(pu)
	dc := checks.DirectClient(s.Cfg.DNSServer)
	defer tc.CloseIdleConnections()
	defer dc.CloseIdleConnections()

	c := s.Cfg.Checks
	var direct checks.EchoResult
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); direct = checks.IPEcho(ctx, dc, c.IPEchoURLs, c.IPEchoRequests) }()
	tunnel := checks.IPEcho(ctx, tc, c.IPEchoURLs, c.IPEchoRequests)
	wg.Wait()

	resp["ok"], resp["tunnel"], resp["direct"] = tunnel.OK, tunnel, direct
	resp["via_vpn"] = tunnel.OK && direct.OK && tunnel.IP != direct.IP
	if !tunnel.OK {
		// By IP only: tells a DNS problem from a dead channel/node.
		pr := checks.IPEcho(ctx, tc, []string{c.TunnelIPProbe}, 1)
		resp["probe"] = map[string]any{"url": c.TunnelIPProbe, "ok": pr.OK, "error": pr.Error}
		resp["error"] = tunnel.Error
		resp["xray_log"] = tail(proc.Stop(), 1500)
	}
	writeJSON(w, http.StatusOK, resp)
}

