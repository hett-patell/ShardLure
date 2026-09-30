package script

import (
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"regexp"
)

type Key struct {
	Type        string
	Fingerprint string // SHA256:<unpadded base64>, as ssh-keygen -l prints it
	Comment     string
}

var keyLine = regexp.MustCompile(`(ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-nistp(?:256|384|521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)\s+(AAAA[0-9A-Za-z+/]+={0,3})(?:[ \t]+([^\s"'\\>|;&]+))?`)

// ExtractKeys finds OpenSSH public keys written by a command. Only a blob
// that is a well-formed key of its labelled type is taken, by OpenSSH's own
// rules (checked against ssh-keygen -l, OpenSSH 9.6): the fields of that
// type in order and nothing after them, a 32-byte ed25519 value, an ECDSA
// point on the named curve, mpints that are not negative and at most 2049
// bytes (2049 only with a leading zero), and an RSA modulus of 1024 to 16384
// bits. A blob whose embedded type does not match its label, or a right
// type string followed by arbitrary bytes, is not a key (the second used to
// be fingerprinted, audit M5), and neither is a 63-bit RSA modulus (final
// audit M6). ssh-keygen hashes the key re-encoded, so an mpint with extra
// leading zeros is hashed in its minimal form: for the keys it takes, the
// fingerprint is ssh-keygen -l's.
func ExtractKeys(command string) []Key {
	var out []Key
	for _, m := range keyLine.FindAllStringSubmatch(command, -1) {
		blob, err := base64.StdEncoding.DecodeString(m[2])
		if err != nil {
			continue
		}
		blob, ok := canonicalKey(m[1], blob)
		if !ok {
			continue
		}
		sum := sha256.Sum256(blob)
		out = append(out, Key{Type: m[1], Fingerprint: "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]), Comment: m[3]})
	}
	return out
}

// canonicalKey parses blob as the SSH wire encoding of a typ public key and
// returns it as ssh-keygen re-encodes it before hashing: the same bytes,
// except that RSA and DSA mpints lose redundant leading zeros.
func canonicalKey(typ string, blob []byte) ([]byte, bool) {
	r := wireReader{b: blob, ok: true}
	if string(r.field()) != typ {
		return nil, false
	}
	var ints [][]byte
	switch typ {
	case "ssh-rsa":
		e, n := r.mpint(), r.mpint()
		// sshkey_check_rsa_length: 1024 <= bits(n) <= 16384.
		if bits := len(n) * 8; len(n) > 0 {
			for c := n[0]; c&0x80 == 0; c <<= 1 {
				bits--
			}
			if bits < 1024 || bits > 16384 {
				return nil, false
			}
		} else {
			return nil, false
		}
		ints = [][]byte{e, n}
	case "ssh-dss":
		ints = [][]byte{r.mpint(), r.mpint(), r.mpint(), r.mpint()} // p, q, g, y
	case "ssh-ed25519":
		r.fixed(32)
	case "sk-ssh-ed25519@openssh.com":
		r.fixed(32)
		r.field() // application
	case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521":
		r.point(typ[len("ecdsa-sha2-"):])
	case "sk-ecdsa-sha2-nistp256@openssh.com":
		r.point("nistp256")
		r.field() // application
	default:
		return nil, false
	}
	if !r.ok || len(r.b) != 0 {
		return nil, false
	}
	if ints == nil {
		return blob, true
	}
	out := appendField(nil, []byte(typ))
	for _, v := range ints {
		if len(v) > 0 && v[0]&0x80 != 0 {
			v = append([]byte{0}, v...) // positive: a sign byte
		}
		out = appendField(out, v)
	}
	return out, true
}

func appendField(b, f []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(f)))
	return append(b, f...)
}

// wireReader reads length-prefixed SSH fields; any short or malformed field
// clears ok, and later reads then return nothing.
type wireReader struct {
	b  []byte
	ok bool
}

func (r *wireReader) field() []byte {
	if !r.ok || len(r.b) < 4 {
		r.ok = false
		return nil
	}
	n := binary.BigEndian.Uint32(r.b)
	if int64(n) > int64(len(r.b)-4) {
		r.ok = false
		return nil
	}
	f := r.b[4 : 4+n]
	r.b = r.b[4+n:]
	return f
}

// mpint reads a non-negative multiple-precision integer as OpenSSH's
// sshbuf_get_bignum2 does and returns its magnitude without leading zeros
// (empty for zero): at most 2049 bytes, and 2049 only with a leading zero.
func (r *wireReader) mpint() []byte {
	f := r.field()
	if !r.ok || len(f) > 0 && f[0]&0x80 != 0 || len(f) > 2049 || len(f) == 2049 && f[0] != 0 {
		r.ok = false
		return nil
	}
	for len(f) > 0 && f[0] == 0 {
		f = f[1:]
	}
	return f
}

func (r *wireReader) fixed(n int) {
	if len(r.field()) != n {
		r.ok = false
	}
}

// point reads a curve name, which must be curve, and a point on it.
func (r *wireReader) point(curve string) {
	if string(r.field()) != curve {
		r.ok = false
		return
	}
	q := r.field()
	var c ecdh.Curve
	switch curve {
	case "nistp256":
		c = ecdh.P256()
	case "nistp384":
		c = ecdh.P384()
	case "nistp521":
		c = ecdh.P521()
	}
	if !r.ok || c == nil {
		r.ok = false
		return
	}
	if _, err := c.NewPublicKey(q); err != nil {
		r.ok = false
	}
}
