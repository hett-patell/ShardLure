package web

import (
	"github.com/networkshard/shardlure/internal/netmatch"
	"net/http"
)

type OriginPolicy = netmatch.OriginPolicy

func NewOriginPolicy(origin string, trusted []string) (OriginPolicy, error) {
	return netmatch.NewOriginPolicy(origin, trusted)
}
func (s *Server) sameOriginRequest(r *http.Request) bool {
	expected, _, err := s.originPolicy.Expected(r)
	if err != nil {
		return false
	}
	supplied, err := netmatch.CanonicalOrigin(r.Header.Get("Origin"))
	return err == nil && supplied == expected
}
