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
// that is a well-formed key of its labelled type is taken: the fields of
// that type in order and nothing after them, a 32-byte ed25519 value, an
// ECDSA point on the named curve. A blob whose embedded type does not match
// its label, or a right type string followed by arbitrary bytes, is not a
// key (ssh-keygen -l refuses both; the second used to be fingerprinted,
// audit M5). For the keys it takes, the fingerprint is ssh-keygen -l's.
func ExtractKeys(command string) []Key {
	var out []Key
	for _, m := range keyLine.FindAllStringSubmatch(command, -1) {
		blob, err := base64.StdEncoding.DecodeString(m[2])
		if err != nil || !wellFormedKey(m[1], blob) {
			continue
		}
		sum := sha256.Sum256(blob)
		out = append(out, Key{Type: m[1], Fingerprint: "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]), Comment: m[3]})
	}
	return out
}

// wellFormedKey parses blob as the SSH wire encoding of a typ public key.
func wellFormedKey(typ string, blob []byte) bool {
	r := wireReader{b: blob, ok: true}
	if string(r.field()) != typ {
		return false
	}
	switch typ {
	case "ssh-rsa":
		r.mpint() // e
		r.mpint() // n
	case "ssh-dss":
		r.mpint() // p
		r.mpint() // q
		r.mpint() // g
		r.mpint() // y
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
		return false
	}
	return r.ok && len(r.b) == 0
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

// mpint reads a positive multiple-precision integer.
func (r *wireReader) mpint() {
	if f := r.field(); len(f) == 0 || f[0]&0x80 != 0 {
		r.ok = false
	}
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
