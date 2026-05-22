package config

import (
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	DataDir string `yaml:"data_dir"`

	AdminIPs []string `yaml:"admin_ips"`

	SSH struct {
		AdminPort    int `yaml:"admin_port"`
		HoneypotPort int `yaml:"honeypot_port"`
	} `yaml:"ssh"`

	Dashboard struct {
		Port        int     `yaml:"port"`
		HomeLat     float64 `yaml:"home_lat"`
		HomeLon     float64 `yaml:"home_lon"`
		HomeCity    string  `yaml:"home_city"`
		HomeCountry string  `yaml:"home_country"`
		HomeCC      string  `yaml:"home_cc"`
	} `yaml:"dashboard"`

	Journal struct {
		Unit string `yaml:"unit"`
	} `yaml:"journal"`

	Cowrie struct {
		Home    string `yaml:"home"`
		JSONLog string `yaml:"json_log"`
	} `yaml:"cowrie"`

	Capture struct {
		Enabled         bool   `yaml:"enabled"`
		EvidenceDir     string `yaml:"evidence_dir"`
		QuarantineFetch bool   `yaml:"quarantine_fetch"`
		MaxBytes        int64  `yaml:"max_bytes"`
		TimeoutSec      int    `yaml:"timeout_sec"`
	} `yaml:"capture"`

	GeoIP struct {
		// MMDB is parsed for forward-compat but not yet read by the
		// geo resolver (only ip-api.com HTTP lookups are wired up).
		// See README roadmap: "GeoLite2 MMDB enrichment".
		MMDB         string `yaml:"mmdb"`
		Enabled      bool   `yaml:"enabled"`
		InsecureHTTP bool   `yaml:"insecure_http"`
	} `yaml:"geoip"`
}

// fallbackDataDir is used when the user has no resolvable HOME (e.g. running
// under a service account without HOME set). Without this guard, Default()
// produced "/.local/share/shardlure" because os.UserHomeDir returned "" and
// the empty string silently joined to "/".
const fallbackDataDir = "/var/lib/shardlure"

func userDataDir() string {
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return fallbackDataDir
	}
	return filepath.Join(home, ".local", "share", "shardlure")
}

func Default() Config {
	dir := userDataDir()
	c := Config{DataDir: dir}
	c.AdminIPs = []string{}
	c.Journal.Unit = "ssh"
	c.SSH.AdminPort = 2222
	c.SSH.HoneypotPort = 22
	c.Dashboard.Port = 8080
	c.Dashboard.HomeLat = 19.0760
	c.Dashboard.HomeLon = 72.8777
	c.Dashboard.HomeCity = "Mumbai"
	c.Dashboard.HomeCountry = "India"
	c.Dashboard.HomeCC = "IN"
	c.Cowrie.Home = filepath.Join(dir, "cowrie")
	c.Cowrie.JSONLog = filepath.Join(dir, "cowrie", "var", "log", "cowrie", "cowrie.json")
	c.Capture.Enabled = true
	c.Capture.QuarantineFetch = true
	c.Capture.MaxBytes = 50 << 20
	c.Capture.TimeoutSec = 45
	return c
}

func Load(path string) (Config, error) {
	c := Default()
	if path == "" {
		path = DefaultConfigPath()
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return c, nil
		}
		return c, err
	}
	if err := yaml.Unmarshal(b, &c); err != nil {
		return c, err
	}
	if c.DataDir == "" {
		c.DataDir = Default().DataDir
	}
	if c.Cowrie.JSONLog == "" {
		c.Cowrie.JSONLog = filepath.Join(c.DataDir, "cowrie", "var", "log", "cowrie", "cowrie.json")
	}
	return c, nil
}

func DefaultConfigPath() string {
	return filepath.Join(userDataDir(), "shardlure.yaml")
}

func (c Config) Save(path string) error {
	if path == "" {
		path = DefaultConfigPath()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

func (c Config) DBPath() string {
	return filepath.Join(c.DataDir, "shardlure.db")
}

func (c Config) CaptureEvidenceDir() string {
	if c.Capture.EvidenceDir != "" {
		return c.Capture.EvidenceDir
	}
	return filepath.Join(c.DataDir, "evidence")
}
