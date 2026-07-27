package netmatch

import (
	"net"
	"testing"
)

func TestIsPublicIP(t *testing.T) {
	tests := []struct {
		name string
		ip   net.IP
		want bool
	}{
		{name: "nil", ip: nil},
		{name: "malformed", ip: net.IP{1, 2, 3}},
		{name: "unspecified IPv4", ip: net.ParseIP("0.0.0.0")},
		{name: "this-network IPv4", ip: net.ParseIP("0.1.2.3")},
		{name: "unspecified IPv6", ip: net.ParseIP("::")},
		{name: "loopback IPv4", ip: net.ParseIP("127.0.0.1")},
		{name: "loopback IPv6", ip: net.ParseIP("::1")},
		{name: "link-local IPv4", ip: net.ParseIP("169.254.169.254")},
		{name: "link-local IPv6", ip: net.ParseIP("fe80::1")},
		{name: "RFC1918 10/8", ip: net.ParseIP("10.1.2.3")},
		{name: "RFC1918 172.16/12", ip: net.ParseIP("172.20.1.2")},
		{name: "RFC1918 192.168/16", ip: net.ParseIP("192.168.1.2")},
		{name: "IPv6 ULA", ip: net.ParseIP("fd12:3456::1")},
		{name: "IPv4-mapped private", ip: net.ParseIP("::ffff:10.1.2.3")},
		{name: "CGNAT", ip: net.ParseIP("100.100.1.2")},
		{name: "TEST-NET-1", ip: net.ParseIP("192.0.2.1")},
		{name: "TEST-NET-2", ip: net.ParseIP("198.51.100.2")},
		{name: "TEST-NET-3", ip: net.ParseIP("203.0.113.3")},
		{name: "IPv6 documentation", ip: net.ParseIP("2001:db8::1")},
		{name: "IPv6 documentation 3fff", ip: net.ParseIP("3fff::1")},
		{name: "benchmarking", ip: net.ParseIP("198.19.255.1")},
		{name: "multicast IPv4", ip: net.ParseIP("224.0.0.1")},
		{name: "multicast IPv6", ip: net.ParseIP("ff02::1")},
		{name: "IETF protocol IPv4", ip: net.ParseIP("192.0.0.8")},
		{name: "IETF protocol IPv6", ip: net.ParseIP("2001::1")},
		{name: "AS112 IPv4", ip: net.ParseIP("192.31.196.1")},
		{name: "AMT IPv4", ip: net.ParseIP("192.52.193.1")},
		{name: "direct delegation AS112 IPv4", ip: net.ParseIP("192.175.48.1")},
		{name: "dummy IPv6 prefix", ip: net.ParseIP("100:0:0:1::1")},
		{name: "direct delegation AS112 IPv6", ip: net.ParseIP("2620:4f:8000::1")},
		{name: "reserved high IPv4", ip: net.ParseIP("240.0.0.1")},
		{name: "limited broadcast", ip: net.ParseIP("255.255.255.255")},
		{name: "NAT64 embedded private", ip: net.ParseIP("64:ff9b::a00:1")},
		{name: "local NAT64 embedded private", ip: net.ParseIP("64:ff9b:1::a00:1")},
		{name: "6to4 embedded private", ip: net.ParseIP("2002:a00:1::")},
		{name: "public IPv4", ip: net.ParseIP("8.8.8.8"), want: true},
		{name: "public IPv4 mapped", ip: net.ParseIP("::ffff:8.8.8.8"), want: true},
		{name: "public IPv6", ip: net.ParseIP("2606:4700:4700::1111"), want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsPublicIP(tt.ip); got != tt.want {
				t.Fatalf("IsPublicIP(%v) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}
