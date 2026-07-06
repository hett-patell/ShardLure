package config

import (
	"fmt"
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

	// RetentionDays controls how long events, enrichment cache entries,
	// artifacts, and TTY transcripts are kept before they are pruned.
	// Set to 0 to disable periodic purging (not recommended for production
	// honeypots). Defaults to 90 days.
	RetentionDays int `yaml:"retention_days"`

	// Intel groups outbound threat-intel sharing destinations. Each
	// destination is opt-in; an empty api_key disables it. Currently
	// only MalwareBazaar (abuse.ch) is wired up.
	Intel struct {
		Bazaar struct {
			// APIKey is the abuse.ch Auth-Key obtained from
			// https://auth.abuse.ch/. Required.
			APIKey string `yaml:"api_key"`
			// Endpoint overrides the upload URL. Defaults to
			// https://mb-api.abuse.ch/api/v1/. Useful for tests.
			Endpoint string `yaml:"endpoint"`
			// Tags are appended to every uploaded sample's tag
			// list (in addition to the per-sample auto-tags).
			// Recommended: ["shardlure", "honeypot"].
			Tags []string `yaml:"tags"`
			// MaxBytes is the upper file-size limit for a single
			// upload. Files larger than this are skipped. Defaults
			// to 32 MiB (MalwareBazaar enforces its own cap server
			// side; this is a client-side safety rail).
			MaxBytes int64 `yaml:"max_bytes"`
			// FreshnessDays bounds how recently the artifact must
			// have been captured. Defaults to 10 (matches abuse.ch
			// submission policy).
			FreshnessDays int `yaml:"freshness_days"`
		} `yaml:"bazaar"`
		AbuseIPDB struct {
			// ReportEnabled is the master opt-in for outbound reporting of
			// confirmed brute-forcers to AbuseIPDB. Reporting stays OFF unless
			// this is true AND SHARDLURE_ABUSEIPDB_KEY is set (the API key is
			// an env secret, reused from the enrichment /check path — never a
			// config field). Enrichment /check reads are unaffected by this.
			ReportEnabled bool `yaml:"report_enabled"`
			// Endpoint overrides the report URL. Defaults to
			// https://api.abuseipdb.com/api/v2/report. Useful for tests.
			Endpoint string `yaml:"endpoint"`
			// Categories are the AbuseIPDB category IDs attached to every
			// report. Defaults to [18, 22] (18=Brute-Force, 22=SSH). See
			// https://www.abuseipdb.com/categories.
			Categories []int `yaml:"categories"`
			// MinProbeScore is the actor ProbeScore floor to report (0-100).
			// Defaults to 60 — only high-confidence brute-forcers.
			MinProbeScore int `yaml:"min_probe_score"`
			// RewindowHours is how long a reported IP is suppressed before it
			// may be reported again (AbuseIPDB permits re-reporting after 15
			// min; we default to 24h to stay well within fair use).
			RewindowHours int `yaml:"rewindow_hours"`
			// Comment is an operator-supplied suffix appended to the generated
			// report comment. The generated comment carries NOTHING that
			// identifies the honeypot host or session.
			Comment string `yaml:"comment"`
		} `yaml:"abuseipdb"`
	} `yaml:"intel"`
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
	c.RetentionDays = 90
	c.Intel.Bazaar.Endpoint = "https://mb-api.abuse.ch/api/v1/"
	c.Intel.Bazaar.Tags = []string{"shardlure", "honeypot"}
	c.Intel.Bazaar.MaxBytes = 32 << 20
	c.Intel.Bazaar.FreshnessDays = 10
	c.Intel.AbuseIPDB.ReportEnabled = false
	c.Intel.AbuseIPDB.Endpoint = "https://api.abuseipdb.com/api/v2/report"
	c.Intel.AbuseIPDB.Categories = []int{18, 22} // 18=Brute-Force, 22=SSH
	c.Intel.AbuseIPDB.MinProbeScore = 60
	c.Intel.AbuseIPDB.RewindowHours = 24
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
	if err := c.Validate(); err != nil {
		return c, err
	}
	return c, nil
}

// Validate rejects nonsensical config values that would otherwise fail far
// from their cause (e.g. a negative port surfaces as an opaque bind error, a
// negative retention silently never purges). It is intentionally lenient about
// zero values that have defined meaning (Port 0 = pick default later, Retention
// 0 = purging disabled by design).
func (c Config) Validate() error {
	checkPort := func(name string, p int) error {
		if p < 0 || p > 65535 {
			return fmt.Errorf("config: %s must be in 0-65535, got %d", name, p)
		}
		return nil
	}
	if err := checkPort("ssh.admin_port", c.SSH.AdminPort); err != nil {
		return err
	}
	if err := checkPort("ssh.honeypot_port", c.SSH.HoneypotPort); err != nil {
		return err
	}
	if err := checkPort("dashboard.port", c.Dashboard.Port); err != nil {
		return err
	}
	if strings.TrimSpace(c.DataDir) == "" {
		return fmt.Errorf("config: data_dir must not be empty")
	}
	if c.RetentionDays < 0 {
		return fmt.Errorf("config: retention_days must be >= 0, got %d", c.RetentionDays)
	}
	if c.Capture.MaxBytes < 0 {
		return fmt.Errorf("config: capture.max_bytes must be >= 0, got %d", c.Capture.MaxBytes)
	}
	if c.Capture.TimeoutSec < 0 {
		return fmt.Errorf("config: capture.timeout_sec must be >= 0, got %d", c.Capture.TimeoutSec)
	}
	if c.Intel.Bazaar.MaxBytes < 0 {
		return fmt.Errorf("config: intel.bazaar.max_bytes must be >= 0, got %d", c.Intel.Bazaar.MaxBytes)
	}
	if c.Intel.AbuseIPDB.MinProbeScore < 0 || c.Intel.AbuseIPDB.MinProbeScore > 100 {
		return fmt.Errorf("config: intel.abuseipdb.min_probe_score must be in 0-100, got %d", c.Intel.AbuseIPDB.MinProbeScore)
	}
	if c.Intel.AbuseIPDB.RewindowHours < 0 {
		return fmt.Errorf("config: intel.abuseipdb.rewindow_hours must be >= 0, got %d", c.Intel.AbuseIPDB.RewindowHours)
	}
	return nil
}

func DefaultConfigPath() string {
	return filepath.Join(userDataDir(), "shardlure.yaml")
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
