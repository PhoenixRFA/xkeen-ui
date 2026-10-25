// Package checks: parsers and probes for router, site and tunnel checks.
package checks

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type PingResult struct {
	Sent    int     `json:"sent"`
	Recv    int     `json:"recv"`
	LossPct int     `json:"loss_pct"`
	MinMs   float64 `json:"min_ms"`
	AvgMs   float64 `json:"avg_ms"`
	MaxMs   float64 `json:"max_ms"`
}

var (
	pingStatRe = regexp.MustCompile(`(\d+) packets transmitted, (\d+) packets received, (\d+)% packet loss`)
	pingRttRe  = regexp.MustCompile(`min/avg/max = ([\d.]+)/([\d.]+)/([\d.]+) ms`)
	addrRe     = regexp.MustCompile(`(?m)^Address(?:\s+\d+)?:\s+(\d{1,3}(?:\.\d{1,3}){3})\b`)
	domainRe   = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)
)

// ParsePing reads busybox ping output.
func ParsePing(out string) PingResult {
	var r PingResult
	if m := pingStatRe.FindStringSubmatch(out); m != nil {
		r.Sent, _ = strconv.Atoi(m[1])
		r.Recv, _ = strconv.Atoi(m[2])
		r.LossPct, _ = strconv.Atoi(m[3])
	}
	if m := pingRttRe.FindStringSubmatch(out); m != nil {
		r.MinMs, _ = strconv.ParseFloat(m[1], 64)
		r.AvgMs, _ = strconv.ParseFloat(m[2], 64)
		r.MaxMs, _ = strconv.ParseFloat(m[3], 64)
	}
	return r
}

// ParseNslookup returns the first IPv4 address listed after the "Name:" line
// (the "Address" line of the DNS server before it is ignored).
func ParseNslookup(out string) (string, bool) {
	i := strings.Index(out, "Name:")
	if i < 0 {
		return "", false
	}
	m := addrRe.FindStringSubmatch(out[i:])
	if m == nil || net.ParseIP(m[1]) == nil {
		return "", false
	}
	return m[1], true
}

// CleanDomain accepts "example.com", "https://example.com/path" and returns a bare ASCII host name.
func CleanDomain(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(strings.TrimPrefix(s, "https://"), "http://")
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSuffix(s, ".")
	for _, r := range s {
		if r > 127 {
			return "", fmt.Errorf("use the punycode form (xn--...) for non-ASCII names")
		}
	}
	if len(s) == 0 || len(s) > 253 || !domainRe.MatchString(s) {
		return "", fmt.Errorf("invalid domain name")
	}
	return s, nil
}

type EchoResult struct {
	OK      bool    `json:"ok"`
	IP      string  `json:"ip,omitempty"`
	TimesMs []int64 `json:"times_ms"`
	AvgMs   int64   `json:"avg_ms"`
	Service string  `json:"service,omitempty"`
	Error   string  `json:"error,omitempty"`
}

func fetchIP(ctx context.Context, c *http.Client, u string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "xkeen-ui")
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 128))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	ip := strings.TrimSpace(string(b))
	if net.ParseIP(ip) == nil {
		return "", fmt.Errorf("unexpected response")
	}
	return ip, nil
}

// IPEcho requests the public IP n times (keep-alive), timing each request.
// The first URL that answers at least once wins.
func IPEcho(ctx context.Context, c *http.Client, urls []string, n int) EchoResult {
	var res EchoResult
	for _, u := range urls {
		res = EchoResult{TimesMs: []int64{}}
		if pu, err := url.Parse(u); err == nil {
			res.Service = pu.Host
		}
		var sum int64
		for i := 0; i < n; i++ {
			t0 := time.Now()
			ip, err := fetchIP(ctx, c, u)
			if err != nil {
				res.Error = err.Error()
				break
			}
			ms := time.Since(t0).Milliseconds()
			res.TimesMs = append(res.TimesMs, ms)
			sum += ms
			res.IP = ip
		}
		if len(res.TimesMs) > 0 {
			res.OK = true
			res.AvgMs = sum / int64(len(res.TimesMs))
			return res
		}
	}
	return res
}

// DirectClient goes straight to the internet and resolves names via the given DNS server.
func DirectClient(dns string) *http.Client {
	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "udp", net.JoinHostPort(dns, "53"))
	}}
	d := &net.Dialer{Timeout: 5 * time.Second, Resolver: r}
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil, DialContext: d.DialContext, MaxIdleConns: 1}}
}

// ProxyClient sends requests through an HTTP proxy.
func ProxyClient(proxy *url.URL) *http.Client {
	return &http.Client{Timeout: 12 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(proxy), MaxIdleConns: 1}}
}
