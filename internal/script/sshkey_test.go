package script

import "testing"

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
