package netmatch

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

var ErrOriginPolicy = errors.New("invalid dashboard origin or trusted proxy configuration")

type OriginPolicy struct {
	origin, scheme, host string
	trusted              []netip.Prefix
}

func CanonicalOrigin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Opaque != "" || (u.Path != "" && u.Path != "/") || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || strings.Contains(raw, "#") {
		return "", ErrOriginPolicy
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", ErrOriginPolicy
	}
	host := strings.ToLower(u.Hostname())
	if host == "" || strings.Contains(host, "%") || strings.ContainsAny(host, " \t\r\n\\/?#@") {
		return "", ErrOriginPolicy
	}
	for _, c := range host {
		if c > 127 || c < 33 {
			return "", ErrOriginPolicy
		}
	}
	if strings.Contains(host, ":") {
		if ip, err := netip.ParseAddr(host); err != nil || !ip.Is6() {
			return "", ErrOriginPolicy
		}
		host = "[" + host + "]"
	}
	port := u.Port()
	if strings.HasSuffix(u.Host, ":") {
		return "", ErrOriginPolicy
	}
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", ErrOriginPolicy
		}
		if !((scheme == "https" && n == 443) || (scheme == "http" && n == 80)) {
			host = net.JoinHostPort(strings.Trim(host, "[]"), strconv.Itoa(n))
		}
	}
	return scheme + "://" + host, nil
}

func NewOriginPolicy(public string, proxies []string) (OriginPolicy, error) {
	var p OriginPolicy
	if public == "" && len(proxies) == 0 {
		return p, nil
	}
	if public == "" || len(proxies) == 0 || len(proxies) > 256 {
		return p, ErrOriginPolicy
	}
	origin, err := CanonicalOrigin(public)
	if err != nil {
		return p, err
	}
	u, _ := url.Parse(origin)
	p.origin, p.scheme, p.host = origin, u.Scheme, u.Host
	for _, raw := range proxies {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			ip, e := netip.ParseAddr(raw)
			if e != nil || ip.Zone() != "" {
				return OriginPolicy{}, ErrOriginPolicy
			}
			ip = ip.Unmap()
			prefix = netip.PrefixFrom(ip, ip.BitLen())
		}
		if prefix.Bits() == 0 || prefix.Addr().Zone() != "" {
			return OriginPolicy{}, ErrOriginPolicy
		}
		if prefix.Addr().Is4In6() {
			if prefix.Bits() <= 96 {
				return OriginPolicy{}, ErrOriginPolicy
			}
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
		}
		p.trusted = append(p.trusted, prefix.Masked())
	}
	return p, nil
}
func (p OriginPolicy) IsTrustedPeer(remote string) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || ip.Zone() != "" {
		return false
	}
	ip = ip.Unmap()
	for _, prefix := range p.trusted {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}
func (p OriginPolicy) Expected(r *http.Request) (string, bool, error) {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if p.IsTrustedPeer(r.RemoteAddr) {
		value, err := CanonicalOrigin(p.scheme + "://" + r.Host)
		if err != nil || value != p.origin {
			return "", false, ErrOriginPolicy
		}
		return p.origin, p.scheme == "https", nil
	}
	origin, err := CanonicalOrigin(scheme + "://" + r.Host)
	return origin, scheme == "https", err
}
