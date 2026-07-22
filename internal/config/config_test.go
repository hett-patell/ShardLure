package config

import (
	"fmt"
	"testing"
)

func TestValidateRejectsBadValues(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Config)
	}{
		{"negative admin port", func(c *Config) { c.SSH.AdminPort = -1 }},
		{"admin port too high", func(c *Config) { c.SSH.AdminPort = 70000 }},
		{"negative honeypot port", func(c *Config) { c.SSH.HoneypotPort = -22 }},
		{"negative dashboard port", func(c *Config) { c.Dashboard.Port = -8080 }},
		{"empty data dir", func(c *Config) { c.DataDir = "" }},
		{"negative retention", func(c *Config) { c.RetentionDays = -1 }},
		{"negative capture max bytes", func(c *Config) { c.Capture.MaxBytes = -1 }},
		{"negative capture timeout", func(c *Config) { c.Capture.TimeoutSec = -5 }},
		{"negative bazaar freshness", func(c *Config) { c.Intel.Bazaar.FreshnessDays = -1 }},
		{"bazaar freshness above ceiling", func(c *Config) { c.Intel.Bazaar.FreshnessDays = 11 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := Default()
			tc.mutate(&c)
			if err := c.Validate(); err == nil {
				t.Fatalf("expected Validate to reject %s, got nil", tc.name)
			}
		})
	}
}

func TestValidateAcceptsBazaarFreshnessRange(t *testing.T) {
	for days := 0; days <= 10; days++ {
		t.Run(fmt.Sprintf("%d_days", days), func(t *testing.T) {
			c := Default()
			c.Intel.Bazaar.FreshnessDays = days
			if err := c.Validate(); err != nil {
				t.Fatalf("Validate rejected freshness_days=%d: %v", days, err)
			}
		})
	}
}

func TestValidateAcceptsDefaultsAndZeroPorts(t *testing.T) {
	c := Default()
	// Port 0 (pick default later) and RetentionDays 0 (purging disabled) are
	// defined, valid states — Validate must not reject them.
	c.SSH.AdminPort = 0
	c.SSH.HoneypotPort = 0
	c.Dashboard.Port = 0
	c.RetentionDays = 0
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate rejected a valid config: %v", err)
	}
}
