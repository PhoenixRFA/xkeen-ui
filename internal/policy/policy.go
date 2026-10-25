// Package policy parses Keenetic RCI output for policies and hotspot clients.
package policy

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type Policy struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Highlight bool   `json:"highlight"`
}

type Client struct {
	MAC      string `json:"mac"`
	IP       string `json:"ip"`
	Name     string `json:"name"`
	Hostname string `json:"hostname"`
	Policy   string `json:"policy"`
	Online   bool   `json:"online"`
}

var (
	idRe  = regexp.MustCompile(`^Policy(\d+)$`)
	macRe = regexp.MustCompile(`^([0-9a-f]{2}:){5}[0-9a-f]{2}$`)
)

// ValidID reports whether s looks like a policy id such as "Policy1".
func ValidID(s string) bool { return idRe.MatchString(s) }

// NormMAC lowercases and validates a MAC address.
func NormMAC(s string) (string, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	return s, macRe.MatchString(s)
}

// ParsePolicies reads /rci/show/ip/policy. Policies are sorted by number.
func ParsePolicies(b []byte, highlight []string) ([]Policy, error) {
	var raw map[string]struct {
		Description string `json:"description"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	hl := map[string]bool{}
	for _, h := range highlight {
		hl[h] = true
	}
	var out []Policy
	for id, p := range raw {
		if !idRe.MatchString(id) {
			continue
		}
		name := p.Description
		if name == "" {
			name = id
		}
		out = append(out, Policy{ID: id, Name: name, Highlight: hl[p.Description]})
	}
	num := func(id string) int { n, _ := strconv.Atoi(idRe.FindStringSubmatch(id)[1]); return n }
	sort.Slice(out, func(i, j int) bool { return num(out[i].ID) < num(out[j].ID) })
	return out, nil
}

// ParseHosts reads /rci/show/ip/hotspot. The display name is name, then hostname, then MAC.
func ParseHosts(b []byte) ([]Client, error) {
	var raw struct {
		Host []struct {
			MAC      string `json:"mac"`
			IP       string `json:"ip"`
			Name     string `json:"name"`
			Hostname string `json:"hostname"`
			Policy   string `json:"policy"`
			Active   bool   `json:"active"`
		} `json:"host"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	var out []Client
	for _, h := range raw.Host {
		mac, ok := NormMAC(h.MAC)
		if !ok {
			continue
		}
		name := h.Name
		if name == "" {
			name = h.Hostname
		}
		if name == "" {
			name = mac
		}
		out = append(out, Client{MAC: mac, IP: h.IP, Name: name, Hostname: h.Hostname, Policy: h.Policy, Online: h.Active})
	}
	return out, nil
}

// SetCommand builds the ndmc command; an empty policy removes the binding (Default).
func SetCommand(mac, policy string) string {
	if policy == "" {
		return fmt.Sprintf("no ip hotspot host %s policy", mac)
	}
	return fmt.Sprintf("ip hotspot host %s policy %s", mac, policy)
}
