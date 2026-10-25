// Package config loads and saves /opt/etc/xkeen-ui/config.json.
package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
)

const DefaultPath = "/opt/etc/xkeen-ui/config.json"

type Auth struct {
	User       string `json:"user"`
	Salt       string `json:"salt"`
	Hash       string `json:"hash"`
	Iterations int    `json:"iterations"`
}

type Paths struct {
	XrayDir    string `json:"xray_dir"`
	InitScript string `json:"init_script"`
	SubUpdate  string `json:"sub_update"`
	SetMain    string `json:"set_main"`
	ErrorLog   string `json:"error_log"`
	SubLog     string `json:"sub_log"`
	BackupDir  string `json:"backup_dir"`
	Ndmc       string `json:"ndmc"`
	RCIURL     string `json:"rci_url"`
}

type Policies struct {
	Highlight []string `json:"highlight"`
}

type Checks struct {
	PingTarget      string   `json:"ping_target"`
	RouterDNSProbe  string   `json:"router_dns_probe"`
	IPSetName       string   `json:"ipset_name"`
	TunnelCheckPort int      `json:"tunnel_check_port"`
	XrayBin         string   `json:"xray_bin"`
	IPEchoURLs      []string `json:"ip_echo_urls"`
	IPEchoRequests  int      `json:"ip_echo_requests"`
	TunnelIPProbe   string   `json:"tunnel_ip_probe"`
}

type Config struct {
	Listen          string   `json:"listen"`
	AllowCIDRs      []string `json:"allow_cidrs"`
	DNSServer       string   `json:"dns_server"`
	SessionTTLHours int      `json:"session_ttl_hours"`
	Auth            Auth     `json:"auth"`
	Paths           Paths    `json:"paths"`
	Policies        Policies `json:"policies"`
	Checks          Checks   `json:"checks"`
	LogTailLines    int      `json:"log_tail_lines"`
	BackupKeep      int      `json:"backup_keep"`
}

func Default() *Config {
	return &Config{
		Listen:          "192.168.1.1:8088",
		AllowCIDRs:      []string{"192.168.1.0/24"},
		DNSServer:       "192.168.1.1",
		SessionTTLHours: 12,
		Auth:            Auth{User: "admin", Iterations: 200000},
		Paths: Paths{
			XrayDir:    "/opt/etc/xray",
			InitScript: "/opt/etc/init.d/S05xkeen",
			SubUpdate:  "/opt/sbin/xray-sub-update",
			SetMain:    "/opt/sbin/set-main-vpn",
			ErrorLog:   "/opt/var/log/xray/error.log",
			SubLog:     "/opt/var/log/xray/sub-update.log",
			BackupDir:  "/opt/etc/xray/backup",
			Ndmc:       "/bin/ndmc",
			RCIURL:     "http://127.0.0.1:79",
		},
		Policies: Policies{Highlight: []string{"xkeen", "xkeen_full"}},
		Checks: Checks{
			PingTarget:      "8.8.8.8",
			RouterDNSProbe:  "ya.ru",
			IPSetName:       "geo_exclude",
			TunnelCheckPort: 10809,
			XrayBin:         "/opt/sbin/xray",
			IPEchoURLs:      []string{"http://api.ipify.org", "http://ifconfig.me/ip"},
			IPEchoRequests:  3,
			TunnelIPProbe:   "http://1.1.1.1",
		},
		LogTailLines: 200,
		BackupKeep:   10,
	}
}

// Load reads path over the defaults, so missing keys keep default values.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := Default()
	if err := json.Unmarshal(b, c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return c, c.Validate()
}

func (c *Config) Validate() error {
	if _, _, err := net.SplitHostPort(c.Listen); err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	for _, s := range c.AllowCIDRs {
		if _, _, err := net.ParseCIDR(s); err != nil {
			return fmt.Errorf("allow_cidrs: %w", err)
		}
	}
	if c.SessionTTLHours <= 0 {
		return fmt.Errorf("session_ttl_hours must be > 0")
	}
	if c.LogTailLines <= 0 || c.LogTailLines > 2000 {
		c.LogTailLines = 200
	}
	return nil
}

// Save writes atomically with mode 0600.
func (c *Config) Save(path string) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
