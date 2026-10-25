// Package xkeen holds pure helpers for subscription, main-vpn.conf and logs.
package xkeen

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

var mainRe = regexp.MustCompile(`^MAIN_REMARK="(.*)"\s*$`)

// ReadMainRemark returns the last MAIN_REMARK="..." value (as the shell would).
func ReadMainRemark(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	val := ""
	for _, line := range strings.Split(string(b), "\n") {
		if m := mainRe.FindStringSubmatch(strings.TrimRight(line, "\r")); m != nil {
			val = m[1]
		}
	}
	return val, nil
}

// LoadRemarks returns the "remarks" of every subscription entry.
func LoadRemarks(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var subs []struct {
		Remarks string `json:"remarks"`
	}
	if err := json.Unmarshal(b, &subs); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(subs))
	for _, s := range subs {
		out = append(out, s.Remarks)
	}
	return out, nil
}

type Part struct {
	Text    string `json:"text"`
	Matches int    `json:"matches"`
	OK      bool   `json:"ok"`
	Remark  string `json:"remark,omitempty"`
}

// Evaluate mirrors xray-main-gen: a part is usable if it is a substring of exactly one remark.
// effective is the remark of the first usable part ("" if none).
func Evaluate(main string, remarks []string) (parts []Part, effective string) {
	for _, t := range strings.Split(main, "|") {
		p := Part{Text: t}
		if t != "" {
			for _, r := range remarks {
				if strings.Contains(r, t) {
					p.Matches++
					p.Remark = r
				}
			}
		}
		p.OK = p.Matches == 1
		if !p.OK {
			p.Remark = ""
		}
		if p.OK && effective == "" {
			effective = p.Remark
		}
		parts = append(parts, p)
	}
	return
}

// ValidateMain rejects values set-main-vpn cannot take safely.
func ValidateMain(s string) error {
	if s == "" || len(s) > 500 || !utf8.ValidString(s) {
		return fmt.Errorf("value must be 1-500 characters of valid UTF-8")
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f || r == '"' || r == '$' || r == '`' || r == '\\' {
			return fmt.Errorf("forbidden character %q", r)
		}
	}
	for _, p := range strings.Split(s, "|") {
		if p == "" {
			return fmt.Errorf("empty part between separators")
		}
	}
	return nil
}

// TailLines returns the last n lines of a file (reads at most 256 KB from the end).
func TailLines(path string, n int) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	const max = 256 << 10
	off := int64(0)
	if st.Size() > max {
		off = st.Size() - max
	}
	buf := make([]byte, st.Size()-off)
	if len(buf) == 0 {
		return nil, nil
	}
	if _, err := f.ReadAt(buf, off); err != nil && err != io.EOF {
		return nil, err
	}
	lines := strings.Split(strings.TrimRight(string(buf), "\n"), "\n")
	if off > 0 && len(lines) > 0 {
		lines = lines[1:] // first line may be cut
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return lines, nil
}

// LastSubAttempt finds the newest timestamped line of sub-update.log that is not a "gen:" line.
// The timestamp is returned as written (router local time), not parsed into a zone.
func LastSubAttempt(path string) (stamp, msg string) {
	lines, err := TailLines(path, 200)
	if err != nil {
		return "", ""
	}
	for i := len(lines) - 1; i >= 0; i-- {
		l := lines[i]
		if len(l) < 21 || l[19] != ' ' {
			continue
		}
		if _, err := time.Parse("2006-01-02 15:04:05", l[:19]); err != nil {
			continue
		}
		if rest := l[20:]; !strings.HasPrefix(rest, "gen:") {
			return l[:19], rest
		}
	}
	return "", ""
}

var secretKeys = map[string]bool{
	"id": true, "uuid": true, "address": true, "publicKey": true,
	"shortId": true, "password": true, "email": true, "spiderX": true,
}

func mask(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			if _, isStr := x.(string); isStr && secretKeys[k] {
				t[k] = "***"
			} else {
				t[k] = mask(x)
			}
		}
	case []any:
		for i := range t {
			t[i] = mask(t[i])
		}
	}
	return v
}

// MaskJSON pretty-prints JSON with secret string values replaced by "***" (key order becomes alphabetical).
func MaskJSON(b []byte) ([]byte, error) {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, err
	}
	return json.MarshalIndent(mask(v), "", "  ")
}

// FilterTest keeps warnings, errors and the verdict from `xray run -test` output.
func FilterTest(out string) string {
	var keep []string
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "[Warning]") || strings.Contains(l, "[Error]") ||
			strings.Contains(l, "Configuration OK") || strings.Contains(strings.ToLower(l), "failed") {
			keep = append(keep, l)
		}
	}
	if len(keep) == 0 {
		return strings.TrimSpace(out)
	}
	return strings.Join(keep, "\n")
}
