package capture

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// FetchResult holds a quarantined download.
type FetchResult struct {
	LocalPath string
	SHA256    string
	Size      int64
	Status    string
	Detail    string
}

// SafeFetcher downloads attacker URLs into an evidence directory with strict limits.
type SafeFetcher struct {
	EvidenceDir string
	MaxBytes    int64
	Timeout     time.Duration
	AdminIPs    []string
	// TestLoopback allows loopback targets (unit tests only).
	TestLoopback bool
	Client       *http.Client
}

func NewSafeFetcher(evidenceDir string, maxBytes int64, timeout time.Duration, adminIPs []string) *SafeFetcher {
	if maxBytes <= 0 {
		maxBytes = 50 << 20
	}
	if timeout <= 0 {
		timeout = 45 * time.Second
	}
	sf := &SafeFetcher{
		EvidenceDir: evidenceDir,
		MaxBytes:    maxBytes,
		Timeout:     timeout,
		AdminIPs:    adminIPs,
	}
	sf.Client = &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return sf.assertSafeURL(req.URL.String())
		},
	}
	return sf
}

func (f *SafeFetcher) assertSafeURL(raw string) error {
	adminIPs := f.AdminIPs
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	default:
		return fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("missing host")
	}
	if ip := net.ParseIP(host); ip != nil {
		if blockedIP(ip, adminIPs, f.TestLoopback) {
			return fmt.Errorf("blocked target %s", ip)
		}
		return nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("dns lookup: %w", err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("no addresses for %s", host)
	}
	for _, ip := range ips {
		if blockedIP(ip, adminIPs, f.TestLoopback) {
			return fmt.Errorf("blocked resolved target %s", ip)
		}
	}
	return nil
}

func assertSafeURL(raw string, adminIPs []string) error {
	return (&SafeFetcher{AdminIPs: adminIPs}).assertSafeURL(raw)
}

func blockedIP(ip net.IP, adminIPs []string, allowLoopback bool) bool {
	if ip.IsLoopback() {
		return !allowLoopback
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate() {
		return true
	}
	for _, a := range adminIPs {
		if a == "" {
			continue
		}
		if ip.Equal(net.ParseIP(a)) {
			return true
		}
	}
	return false
}

// Fetch downloads url into evidence/quarantine/<sha256> (mode 0600). Never executes content.
func (f *SafeFetcher) Fetch(ctx context.Context, rawURL string) (*FetchResult, error) {
	if err := f.assertSafeURL(rawURL); err != nil {
		return &FetchResult{Status: "blocked", Detail: err.Error()}, err
	}
	dir := filepath.Join(f.EvidenceDir, "quarantine")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "ShardLure-Evidence/1.0")

	resp, err := f.Client.Do(req)
	if err != nil {
		return &FetchResult{Status: "failed", Detail: err.Error()}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		detail := fmt.Sprintf("http %d", resp.StatusCode)
		return &FetchResult{Status: "failed", Detail: detail}, fmt.Errorf("%s", detail)
	}

	if cl := resp.ContentLength; cl > f.MaxBytes {
		return &FetchResult{Status: "blocked", Detail: "content-length too large"}, fmt.Errorf("content-length %d exceeds limit", cl)
	}

	tmp, err := os.CreateTemp(dir, "fetch-*.part")
	if err != nil {
		return nil, err
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}()

	h := sha256.New()
	n, err := io.Copy(tmp, io.TeeReader(io.LimitReader(resp.Body, f.MaxBytes+1), h))
	if err != nil {
		return &FetchResult{Status: "failed", Detail: err.Error()}, err
	}
	if n > f.MaxBytes {
		return &FetchResult{Status: "blocked", Detail: "body too large"}, fmt.Errorf("body exceeds %d bytes", f.MaxBytes)
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}

	sum := hex.EncodeToString(h.Sum(nil))
	final := filepath.Join(dir, sum)
	if err := os.Rename(tmpPath, final); err != nil {
		if os.IsExist(err) || fileExists(final) {
			_ = os.Remove(tmpPath)
		} else {
			return nil, err
		}
	}
	_ = os.Chmod(final, 0o600)

	return &FetchResult{
		LocalPath: final,
		SHA256:    sum,
		Size:      n,
		Status:    "fetched",
	}, nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
