package web

import (
	"net/http"
	"net/url"
	"strings"
)

func sameOriginRequest(r *http.Request) bool {
	origin, err := url.Parse(r.Header.Get("Origin"))
	if err != nil || origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" {
		return false
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	// Do not trust forwarded headers from arbitrary direct clients.
	return origin.Scheme == scheme && strings.EqualFold(origin.Host, r.Host)
}
