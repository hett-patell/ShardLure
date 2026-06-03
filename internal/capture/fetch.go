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
				return fmt.Errorf("too many redirects")
			}
			return sf.assertSafeURL(req.URL.String())
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
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	// Literal IP: validate once, dial directly.
	if ip := net.ParseIP(host); ip != nil {
		if blockedIP(ip, f.AdminIPs, f.TestLoopback) {
			return nil, fmt.Errorf("blocked target %s", ip)
		}
		var d net.Dialer
		return d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
	}
	// Hostname: resolve, filter, take the first survivor.
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("dns lookup %s: %w", host, err)
	}
	for _, ip := range ips {
		if blockedIP(ip, f.AdminIPs, f.TestLoopback) {
			// Any blocked answer in the set is fatal: an attacker
			// who controls DNS could otherwise rotate through good
			// and bad IPs and the runtime might pick a bad one.
			return nil, fmt.Errorf("blocked resolved target %s for %s", ip, host)
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no addresses for %s", host)
	}
	var d net.Dialer
	return d.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
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

// reservedRanges are address blocks the SSRF guard must reject but that the
// net.IP predicates below do NOT cover:
//   - 100.64.0.0/10  CGNAT (RFC 6598) — routable internal range on many cloud
//     hosts; IsPrivate() is false for it.
//   - 198.18.0.0/15  benchmarking (RFC 2544) — IsPrivate() false.
//   - 192.0.0.0/24   IETF protocol assignments.
// (169.254.169.254 cloud metadata is already caught by IsLinkLocalUnicast.)
var reservedRanges = func() []*net.IPNet {
	var out []*net.IPNet
	for _, c := range []string{"100.64.0.0/10", "198.18.0.0/15", "192.0.0.0/24"} {
		if _, n, err := net.ParseCIDR(c); err == nil {
			out = append(out, n)
		}
	}
	return out
}()

func blockedIP(ip net.IP, adminIPs []string, allowLoopback bool) bool {
	// Unspecified (0.0.0.0 / ::) connects to localhost on Linux, so it must be
	// blocked unless loopback is explicitly allowed (tests only).
	if ip.IsUnspecified() {
		return !allowLoopback
	}
	if ip.IsLoopback() {
		return !allowLoopback
	}
	// IsPrivate covers 10/8, 172.16/12, 192.168/16, fc00::/7 only — the
	// reservedRanges and multicast checks fill the gaps.
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate() ||
		ip.IsMulticast() || ip.IsInterfaceLocalMulticast() {
		return true
	}
	for _, n := range reservedRanges {
		if n.Contains(ip) {
			return true
		}
	}
	// adminIPs entries may be bare IPs or CIDR ranges. The old loop compared
	// only ip.Equal(net.ParseIP(a)), so a CIDR entry parsed to nil and matched
	// nothing — meaning an admin range was NOT exempted from being a fetch
	// target. netmatch handles both forms.
	return netmatch.New(adminIPs).HasIP(ip)
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
