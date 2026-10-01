package script

import (
	"encoding/base64"
	"encoding/binary"
	bigpkg "math/big"
	"strings"
	"testing"
)

const (
	testED25519 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKBT1fubDzcjP8Ntf33MZwaTgCpwTQRaj7IrSvXO0lBU mdrfckr"
	testRSA     = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC/47d8xbCuUjYsBrxtmLjL4FDUe3BPIemNktjPYnojUZA9R/xpZ7a66PuzH2i2yvy33Fg9Jpg/ejzudz7ksvXy8KhOv++o4NdbAKVMnSRdTwHjUUokGRtG7+hTeBAKwjP+CiFpxu0HbHpOgBpsm3uJswTZmPk18dn3LKucQB2Ikw== test-rsa"
)

func TestExtractKeysMatchesSSHKeygen(t *testing.T) {
	cmd := `cd ~ && echo "` + testED25519 + `" >> .ssh/authorized_keys && echo '` + testRSA + `'>>.ssh/authorized_keys`
	keys := ExtractKeys(cmd)
	want := []Key{
		{Type: "ssh-ed25519", Fingerprint: "SHA256:a3pXoOM5a2tpPZaM56vV25nc+/JCaTsQNGnx6Na1k8I", Comment: "mdrfckr"},
		{Type: "ssh-rsa", Fingerprint: "SHA256:MFVG9OVG2g61VtrAFp9fBDhfN6wLIZM124oJHVji5Kg", Comment: "test-rsa"},
	}
	if len(keys) != len(want) {
		t.Fatalf("got %+v", keys)
	}
	for i := range want {
		if keys[i] != want[i] {
			t.Errorf("key %d = %+v, want %+v", i, keys[i], want[i])
		}
	}
}

func TestExtractKeysRejectsMismatchedBlob(t *testing.T) {
	if k := ExtractKeys("ssh-rsa AAAAC3NzaC1lZDI1NTE5AAAAIKBT1fubDzcjP8Ntf33MZwaTgCpwTQRaj7IrSvXO0lBU x"); len(k) != 0 {
		t.Fatalf("accepted a mismatched blob: %+v", k)
	}
}

// Vectors checked with ssh-keygen -lf (OpenSSH 9.x); the sk keys were
// assembled from their wire format (an ed25519 value and a real P-256
// point) and ssh-keygen accepts both.
const (
	testECDSA384 = "ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBJJgcY3P1NKXaJihUFAxsHKfztByslvQ9kNmQDYcbqlzRumPug/p5oemTPOaUy6O6k9FbyBJ7/N3s/FQG3K13dcMTgbWoDLoByRmAhTqM/Hp9cTbMF6eu2Q0CHA8n/Vk9A== ec-test"
	testDSS      = "ssh-dss AAAAB3NzaC1kc3MAAACBAOO0S+IvOKmQq+vRHpFWCZrhIPuqPSZ0yUavwyOaNCR0qXqI3D8IU2n7qr1MS6Mqpop1EoQpYHCMddJ2CTHtAXgf22Pp+ndLMrECZGUbOxgsAqLSNNV45JIDdnmH5pdxTwL00K/HQukNMj2r6m6UPmTYjNbbvhkrNb8K5NuYwg5HAAAAFQDZKTr4Ne5CWYodscppNPrMNXZVfQAAAIAb182ehpTfw+rhuVN2AFiTvLhI299UA7nYZ5Hhv5RZpJjodhFzbZ/qS8MRXEnxyBwwBL9LmEhEdIakinth00ue/JUXQ+FbeqqKLi8hEKyTUENd+MwHUNU8eZjvU0ad9JO7uwbxJd/CXh0pA6PzQo47Vh70BqjtXIEUMEMCxqVhNgAAAIEAk6WMoLpOhPDAiJ1m/0D5++hAKghFtGXT6r9wAaOjJlYx/PR6DfqAGHidhDBBLXNF+h/xzCT7KuNyBVa8MUrR6i8vncRmd52siYoeyNMJ1PhcGyJ+Bw+uEU3P1cRUQfejd02vMu5jue83DLltAar+vvqA5Qir9D/nM7f43LIP1xA= dss-test"
	testSKEd     = "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fAAAABHNzaDo= sk-test"
	testSKEc     = "sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAAAIbmlzdHAyNTYAAABBBF+Uzbj8GvonOorfqPDv2TATzSg1cUbsJFIZOYpSKzVtOdeUEAdNV1TKri0SvBqEulyzM2CmeeDEXLLJnwuoZoQAAAAEc3NoOg== sk2"
)

func TestExtractKeysOtherTypes(t *testing.T) {
	for _, tc := range []struct{ line, typ, fp, comment string }{
		{testECDSA384, "ecdsa-sha2-nistp384", "SHA256:W/CpS8Rxb9oPkqN60lPrEpc+Hv6nb3wxnfxQ6NBJiCM", "ec-test"},
		{testDSS, "ssh-dss", "SHA256:ZIy4Hr0KEfYMXr0pVmyDfgnbcndcWCKPfswaqHBKgNg", "dss-test"},
		{testSKEd, "sk-ssh-ed25519@openssh.com", "SHA256:/p0CbeE3dk2SyW1OXXsThGc12ezDVD8eGw2/vtztDfk", "sk-test"},
		{testSKEc, "sk-ecdsa-sha2-nistp256@openssh.com", "SHA256:TgcUmA0jZoq6lOCFDVHb+PoPMPW1Fjb8y30Iw9Z+0uo", "sk2"},
	} {
		k := ExtractKeys(`echo "` + tc.line + `" >> ~/.ssh/authorized_keys`)
		if len(k) != 1 || k[0] != (Key{Type: tc.typ, Fingerprint: tc.fp, Comment: tc.comment}) {
			t.Errorf("%s: got %+v", tc.typ, k)
		}
	}
}

// A blob must be a well-formed key of its type, as ssh-keygen -l requires:
// a right type string followed by arbitrary bytes is not a key (audit M5).
func TestExtractKeysRejectsMalformedBlobs(t *testing.T) {
	for _, line := range []string{
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5Z2FyYmFnZS1ieXRlcy1oZXJl bad",                                                              // type + garbage
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKBT1fubDzcjP8Ntf33MZwaTgCpwTQRaj7IrSvXO0lBUAAAA x",                                    // trailing bytes
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKBT1fubDzcjP8Ntf33MZwaTgCpwTQRaj7IrSvXO0l x",                                          // truncated
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKBT1fubDzcjP8Ntf33MZwaTgCpwTQRaj7IrSvXO0lB! x",                                        // invalid base64
		"sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAAAIbmlzdHAyNTYAAAABBAAAAARzc2g6 x", // point off the curve
	} {
		if k := ExtractKeys(line); len(k) != 0 {
			t.Errorf("accepted %q: %+v", line, k)
		}
	}
	// A missing comment, and a key followed directly by a redirection.
	if k := ExtractKeys(`echo ` + testED25519[:len(testED25519)-8] + `>>f`); len(k) != 1 || k[0].Comment != "" {
		t.Errorf("no comment: %+v", k)
	}
	if k := ExtractKeys(`echo "` + testED25519 + `">>f`); len(k) != 1 || k[0].Comment != "mdrfckr" {
		t.Errorf("comment before >>: %+v", k)
	}
}

// RSA and DSA keys follow OpenSSH's mpint and modulus rules, and a blob
// with redundant leading zeros hashes in the minimal form ssh-keygen
// re-encodes (final audit M6). Every fingerprint and refusal below is
// ssh-keygen -l's (OpenSSH 9.6p1) on the same blob.
func TestExtractKeysFollowsSSHKeygenRules(t *testing.T) {
	fields := func(line string) [][]byte {
		b, err := base64.StdEncoding.DecodeString(strings.Fields(line)[1])
		if err != nil {
			t.Fatal(err)
		}
		var out [][]byte
		for len(b) >= 4 {
			n := binary.BigEndian.Uint32(b)
			out, b = append(out, b[4:4+n]), b[4+n:]
		}
		return out
	}
	line := func(fs ...[]byte) string {
		var b []byte
		for _, f := range fs {
			b = appendField(b, f)
		}
		return string(fs[0]) + " " + base64.StdEncoding.EncodeToString(b) + " x"
	}
	big := func(bits int) []byte { // 2^(bits-1)+1 as an mpint
		b := make([]byte, (bits+7)/8)
		b[0], b[len(b)-1] = 1<<((bits-1)%8), 1
		if b[0]&0x80 != 0 {
			b = append([]byte{0}, b...)
		}
		return b
	}
	r := fields(testRSA)
	typ, e, n := r[0], r[1], r[2]
	half := new(bigpkg.Int).Rsh(new(bigpkg.Int).SetBytes(n), 1).Bytes()
	const rsaFP = "SHA256:MFVG9OVG2g61VtrAFp9fBDhfN6wLIZM124oJHVji5Kg"
	for _, tc := range []struct{ name, line, fp string }{
		{"e with a leading zero", line(typ, append([]byte{0}, e...), n), rsaFP},
		{"n with leading zeros", line(typ, e, append([]byte{0, 0}, n...)), rsaFP},
		{"n with five leading zeros", line(typ, e, append(make([]byte, 5), n...)), rsaFP},
		{"e empty (zero)", line(typ, nil, n), "SHA256:Vji8eqgHS4fPGAkvNrVkYc60DUtCZhTrWDY7v/XVXkU"},
		{"e of 2049 bytes with a leading zero", line(typ, append([]byte{0, 1}, make([]byte, 2047)...), n), "SHA256:df+Upvr2B3sn7dfbFjeAkMH9ejeJNrprNbADtlgVXeI"},
		{"n of 16384 bits", line(typ, e, big(16384)), "SHA256:R79tKCrT82fagTFW5iOxVjaGA3yjEpHnc4enARbBJns"},
		{"n of 1023 bits", line(typ, e, half), ""},
		{"n of 16385 bits", line(typ, e, big(16385)), ""},
		{"n negative", line(typ, e, n[1:]), ""},
		{"n empty", line(typ, e, nil), ""},
		{"e of 2049 bytes", line(typ, append([]byte{1}, make([]byte, 2048)...), n), ""},
		{"e of 2050 bytes", line(typ, append([]byte{0, 0, 1}, make([]byte, 2047)...), n), ""},
		{"the auditor's 63-bit n", "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAACH8BAgMEBQYH x", ""},
	} {
		k := ExtractKeys(tc.line)
		switch {
		case tc.fp == "" && len(k) != 0:
			t.Errorf("%s: accepted %+v", tc.name, k)
		case tc.fp != "" && (len(k) != 1 || k[0].Fingerprint != tc.fp):
			t.Errorf("%s: got %+v, want %s", tc.name, k, tc.fp)
		}
	}
	d := fields(testDSS)
	for _, tc := range []struct{ name, line, fp string }{
		{"q with a leading zero", line(d[0], d[1], append([]byte{0}, d[2]...), d[3], d[4]), "SHA256:ZIy4Hr0KEfYMXr0pVmyDfgnbcndcWCKPfswaqHBKgNg"},
		{"y empty (zero)", line(d[0], d[1], d[2], d[3], nil), "SHA256:IEE7HBSeyD7nSToRv+P6LhQ5LHrjXhrIULY0LBhSsBo"},
	} {
		if k := ExtractKeys(tc.line); len(k) != 1 || k[0].Fingerprint != tc.fp {
			t.Errorf("dss %s: got %+v, want %s", tc.name, k, tc.fp)
		}
	}
}
