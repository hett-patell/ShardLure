package netmatch

import "net"

// IsPublicIP reports whether ip is globally routable and suitable for an
// outbound fetch or abuse report. net.IP.IsGlobalUnicast alone is not enough:
// it returns true for several special-use ranges, including TEST-NET, CGNAT,
// and benchmarking addresses.
func IsPublicIP(ip net.IP) bool {
	if ip == nil {
		return false
	}

	if v4 := ip.To4(); v4 != nil {
		if !v4.IsGlobalUnicast() {
			return false
		}
		return !inAnyRange(v4, nonPublicIPv4Ranges)
	}

	v6 := ip.To16()
	if v6 == nil || !v6.IsGlobalUnicast() {
		return false
	}
	return !inAnyRange(v6, nonPublicIPv6Ranges)
}

func inAnyRange(ip net.IP, ranges []*net.IPNet) bool {
	for _, ipnet := range ranges {
		if ipnet.Contains(ip) {
			return true
		}
	}
	return false
}

// These are the special-use blocks that net.IP.IsGlobalUnicast still treats
// as unicast. Keeping the list here gives capture and outbound reporting one
// conservative definition of a public address.
var nonPublicIPv4Ranges = mustIPNets(
	"0.0.0.0/8",       // current network / unspecified
	"10.0.0.0/8",      // RFC 1918
	"100.64.0.0/10",   // shared address space (CGNAT)
	"127.0.0.0/8",     // loopback
	"169.254.0.0/16",  // link-local
	"172.16.0.0/12",   // RFC 1918
	"192.0.0.0/24",    // IETF protocol assignments
	"192.0.2.0/24",    // TEST-NET-1
	"192.31.196.0/24", // AS112-v4
	"192.52.193.0/24", // Automatic Multicast Tunneling
	"192.88.99.0/24",  // deprecated 6to4 relay anycast
	"192.168.0.0/16",  // RFC 1918
	"192.175.48.0/24", // direct delegation AS112 service
	"198.18.0.0/15",   // benchmarking
	"198.51.100.0/24", // TEST-NET-2
	"203.0.113.0/24",  // TEST-NET-3
	"224.0.0.0/4",     // multicast
	"240.0.0.0/4",     // reserved and limited broadcast
)

var nonPublicIPv6Ranges = mustIPNets(
	"::/128",            // unspecified
	"::1/128",           // loopback
	"64:ff9b::/96",      // well-known NAT64 prefix
	"64:ff9b:1::/48",    // local-use NAT64 prefix
	"100::/64",          // discard-only
	"100:0:0:1::/64",    // dummy IPv6 prefix
	"2001::/23",         // IETF protocol assignments
	"2001:db8::/32",     // documentation
	"2002::/16",         // 6to4
	"2620:4f:8000::/48", // direct delegation AS112 service
	"3fff::/20",         // documentation
	"5f00::/16",         // segment-routing SIDs
	"fc00::/7",          // unique local
	"fe80::/10",         // link-local
	"ff00::/8",          // multicast
)

func mustIPNets(cidrs ...string) []*net.IPNet {
	ranges := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			panic("netmatch: invalid static CIDR " + cidr)
		}
		ranges = append(ranges, ipnet)
	}
	return ranges
}
