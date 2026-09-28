package script

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"regexp"
)

type Key struct {
	Type        string
	Fingerprint string // SHA256:<unpadded base64>, identical to ssh-keygen -l
	Comment     string
}

var keyLine = regexp.MustCompile(`(ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-nistp(?:256|384|521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)\s+(AAAA[0-9A-Za-z+/]+={0,3})(?:[ \t]+([^\s"'\\>|;&]+))?`)

// ExtractKeys finds OpenSSH public keys written by a command. A blob whose
// embedded type does not match its label is rejected.
func ExtractKeys(command string) []Key {
	var out []Key
	for _, m := range keyLine.FindAllStringSubmatch(command, -1) {
		blob, err := base64.StdEncoding.DecodeString(m[2])
		if err != nil || len(blob) < 4 {
			continue
		}
		n := binary.BigEndian.Uint32(blob[:4])
		if int64(n) > int64(len(blob)-4) || string(blob[4:4+n]) != m[1] {
			continue
		}
		sum := sha256.Sum256(blob)
		out = append(out, Key{Type: m[1], Fingerprint: "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]), Comment: m[3]})
	}
	return out
}
