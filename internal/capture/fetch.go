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
	"sync"
	"time"

	"github.com/networkshard/shardlure/internal/netmatch"
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

	// adminSet is the parsed AdminIPs matcher, built once. blockedIP runs
	// per dial and per resolved DNS answer; rebuilding the set (string +
	// CIDR parsing, map allocs) on every call was pure per-request waste.
	adminSetOnce sync.Once
	adminSet     *netmatch.Set
}

// adminMatcher returns the lazily-built AdminIPs matcher. Lazy (rather than
// set in NewSafeFetcher) so zero-value construction in tests keeps working;
// AdminIPs must not be mutated after first use.
func (f *SafeFetcher) adminMatcher() *netmatch.Set {
	f.adminSetOnce.Do(func() { f.adminSet = netmatch.New(f.AdminIPs) })
	return f.adminSet
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
	// Custom transport: every TCP dial routes through safeDial, which
	// re-resolves the hostname against the SSRF guard and connects
	// directly to a validated IP. This closes the TOCTOU between
	// assertSafeURL's lookup and the http.Client's own DNS resolution
	// (DNS rebinding: first answer benign, second answer 169.254...).
	transport := &http.Transport{
		DialContext:           sf.safeDial,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		IdleConnTimeout:       30 * time.Second,
		MaxIdleConns:          4,
		DisableKeepAlives:     true,
	}
	sf.Client = &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return &captureError{status: "invalid", detail: "too many redirects"}
			}
			return sf.assertSafeURLContext(req.Context(), req.URL.String())
		},
	}
	return sf
}

// safeDial resolves the target host through the same allow-list that
// assertSafeURL uses, picks the first non-blocked IP, and dials it
// directly. The connection thus targets an IP we just inspected -
// the runtime can't be tricked into connecting to a different
// address than the one we approved.
func (f *SafeFetcher) safeDial(ctx context.Context, network, address string) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, safeCaptureError(err, "dial cancelled")
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, &captureError{status: "invalid", detail: "invalid target address"}
	}
	// Literal IP: validate once, dial directly.
	if ip := net.ParseIP(host); ip != nil {
		if blockedIP(ip, f.adminMatcher(), f.TestLoopback) {
			return nil, &captureError{status: "blocked", detail: "blocked target address"}
		}
		var d net.Dialer
		return d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
	}
	// Hostname: resolve, filter, take the first survivor.
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, safeCaptureError(err, "dns lookup failed")
	}
	for _, ip := range ips {
		if blockedIP(ip, f.adminMatcher(), f.TestLoopback) {
			// Any blocked answer in the set is fatal: an attacker
			// who controls DNS could otherwise rotate through good
			// and bad IPs and the runtime might pick a bad one.
			return nil, &captureError{status: "blocked", detail: "blocked resolved target"}
		}
	}
	if len(ips) == 0 {
		return nil, safeCaptureError(nil, "dns returned no addresses")
	}
	var d net.Dialer
	return d.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
}

func (f *SafeFetcher) assertSafeURL(raw string) error {
	return f.assertSafeURLContext(context.Background(), raw)
}

func (f *SafeFetcher) assertSafeURLContext(ctx context.Context, raw string) error {
	if err := ctx.Err(); err != nil {
		return safeCaptureError(err, "validation cancelled")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return &captureError{status: "invalid", detail: "invalid URL"}
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	default:
		return &captureError{status: "invalid", detail: "unsupported URL scheme"}
	}
	host := u.Hostname()
	if host == "" {
		return &captureError{status: "invalid", detail: "missing URL host"}
	}
	if ip := net.ParseIP(host); ip != nil {
		if blockedIP(ip, f.adminMatcher(), f.TestLoopback) {
			return &captureError{status: "blocked", detail: "blocked target address"}
		}
		return nil
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return safeCaptureError(err, "dns lookup failed")
	}
	if len(ips) == 0 {
		return safeCaptureError(nil, "dns returned no addresses")
	}
	for _, ip := range ips {
		if blockedIP(ip, f.adminMatcher(), f.TestLoopback) {
			return &captureError{status: "blocked", detail: "blocked resolved target"}
		}
	}
	return nil
}

func blockedIP(ip net.IP, admin *netmatch.Set, allowLoopback bool) bool {
	// Unspecified (0.0.0.0 / ::) connects to localhost on Linux, so it must be
	// blocked unless loopback is explicitly allowed (tests only).
	if allowLoopback && (ip.IsUnspecified() || ip.IsLoopback()) {
		return false
	}
	if !netmatch.IsPublicIP(ip) {
		return true
	}

	// admin entries may be bare IPs or CIDR ranges (netmatch handles both) —
	// admin addresses are never legitimate fetch targets.
	return admin.HasIP(ip)
}

// Fetch downloads url into evidence/quarantine/<sha256> (mode 0600). Never executes content.
func (f *SafeFetcher) Fetch(ctx context.Context, rawURL string) (*FetchResult, error) {
	// Include DNS validation and body/filesystem work in the same total budget,
	// not just Client.Do. A stopped daemon must not start another lookup.
	if f.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, f.Timeout)
		defer cancel()
	}
	if err := f.assertSafeURLContext(ctx, rawURL); err != nil {
		return captureFailure(err, "URL validation failed")
	}
	dir := filepath.Join(f.EvidenceDir, "quarantine")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return captureFailure(err, "cannot create quarantine directory")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return terminalCaptureFailure("invalid", "invalid HTTP request")
	}
	req.Header.Set("User-Agent", "ShardLure-Evidence/1.0")

	resp, err := f.Client.Do(req)
	if err != nil {
		return captureFailure(err, "HTTP request failed")
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		detail := fmt.Sprintf("http %d", resp.StatusCode)
		status := "failed"
		// Request/auth/not-found failures will not improve with an identical
		// retry. Timeouts, Too Early, throttling and server failures may.
		if resp.StatusCode >= 400 && resp.StatusCode < 500 &&
			resp.StatusCode != 408 && resp.StatusCode != 425 && resp.StatusCode != 429 {
			status = "failed_permanently"
		}
		return terminalCaptureFailure(status, detail)
	}
	if resp.StatusCode == http.StatusPartialContent || resp.Header.Get("Content-Range") != "" {
		return terminalCaptureFailure("invalid", "partial HTTP response")
	}

	if cl := resp.ContentLength; cl > f.MaxBytes {
		return terminalCaptureFailure("blocked", "content-length too large")
	}

	tmp, err := os.CreateTemp(dir, "fetch-*.part")
	if err != nil {
		return captureFailure(err, "cannot create quarantine file")
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}()

	h := sha256.New()
	n, err := io.Copy(tmp, io.TeeReader(io.LimitReader(resp.Body, f.MaxBytes+1), h))
	if err != nil {
		return captureFailure(err, "cannot read or store response body")
	}
	if err := ctx.Err(); err != nil {
		return captureFailure(err, "capture cancelled")
	}
	if n > f.MaxBytes {
		return terminalCaptureFailure("blocked", "body too large")
	}
	if n == 0 {
		// A 200 with an empty body is not a payload (parked host, dead drop
		// point). Report "empty", not "fetched", so it can never be treated
		// as a captured sample downstream.
		return &FetchResult{Status: "empty", Detail: "zero-byte body"}, nil
	}
	if err := tmp.Close(); err != nil {
		return captureFailure(err, "cannot close quarantine file")
	}

	sum := hex.EncodeToString(h.Sum(nil))
	final := filepath.Join(dir, sum)
	if err := os.Rename(tmpPath, final); err != nil {
		if os.IsExist(err) || fileExists(final) {
			_ = os.Remove(tmpPath)
		} else {
			return captureFailure(err, "cannot finalize quarantine file")
		}
	}
	if err := os.Chmod(final, 0o600); err != nil {
		return captureFailure(err, "cannot secure quarantine file")
	}

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
