package config

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type Config struct {
	DataDir string `yaml:"data_dir"`

	AdminIPs []string `yaml:"admin_ips"`

	SSH struct {
		AdminPort   int `yaml:"admin_port"`
		HoneypotPort int `yaml:"honeypot_port"`
	} `yaml:"ssh"`

	Dashboard struct {
		Port int `yaml:"port"`
	} `yaml:"dashboard"`

	Journal struct {
		Unit string `yaml:"unit"`
	} `yaml:"journal"`

	Cowrie struct {
		Home    string `yaml:"home"`
		JSONLog string `yaml:"json_log"`
	} `yaml:"cowrie"`

	GeoIP struct {
		MMDB string `yaml:"mmdb"`
	} `yaml:"geoip"`
}

func Default() Config {
	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, ".local", "share", "shardlure")
	c := Config{DataDir: dir}
	c.AdminIPs = []string{}
	c.Journal.Unit = "ssh"
	c.SSH.AdminPort = 2222
	c.SSH.HoneypotPort = 22
	c.Dashboard.Port = 8080
	c.Cowrie.Home = filepath.Join(dir, "cowrie")
	c.Cowrie.JSONLog = filepath.Join(dir, "cowrie", "var", "log", "cowrie", "cowrie.json")
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
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "share", "shardlure", "shardlure.yaml")
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
