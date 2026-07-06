package models

import "time"

type Source string

const (
	SourceJournal Source = "journal"
	SourceCowrie  Source = "cowrie"
)

type EventKind string

const (
	KindInvalidUser EventKind = "invalid_user"
	KindFailedPass  EventKind = "failed_password"
	KindFailedKey   EventKind = "failed_publickey"
	KindAccepted    EventKind = "accepted"
	KindConnect     EventKind = "connect"
	// KindClientVersion is Cowrie's cowrie.client.version — the SSH client
	// banner/identity announcement (carries the client's `version` string in
	// ssh_client; the HASSH fingerprint is a SEPARATE cowrie.client.kex event,
	// stamped onto session events during ingest). It co-occurs with KindConnect
	// at session start, so it is tracked separately rather than folded into
	// KindConnect, which would double-count every session as two connections
	// (inflating event counts, attempt rates, and probe score).
	KindClientVersion EventKind = "client_version"
	KindCommand       EventKind = "command"
	KindFileUp        EventKind = "file_upload"
	KindFileDown      EventKind = "file_download"
	KindTunnel        EventKind = "tunnel"
)

type Event struct {
	ID        int64
	TS        time.Time
	Source    Source
	Kind      EventKind
	SrcIP     string
	SrcPort   int
	Username  string
	Password  string
	SessionID string
	HASSH     string
	SSHClient string
	Command   string
	SHA256    string
	Filename  string
	// DstIP/DstPort are the forwarding destination on cowrie direct-tcpip
	// (proxy/pivot) events — where the attacker tried to tunnel THROUGH the
	// honeypot to. Empty/0 on all other event kinds. Kept as first-class
	// fields rather than overloading Command/Filename (which feed Top
	// Commands / IOC extraction).
	DstIP   string
	DstPort int
	Raw     string
	ActorID string
}

type Actor struct {
	ID              string
	Source          Source
	PrimaryIP       string
	Playbook        string
	Intent          string
	Confidence      int
	FirstSeen       time.Time
	LastSeen        time.Time
	EventCount      int
	UniqueUsers     int
	AttemptsPerHour float64
	HASSH           string
	SSHClient       string
	UsernameHash    string
	// Campaigns is a free-form, comma-separated list of operator-assigned
	// tags (e.g. "mirai-variant,torproxy"). Reserved for manual annotation
	// and future automated campaign correlation — clustering does not
	// populate it today.
	Campaigns string
	// ProbeScore is 0-100. Populated by actor.cowrieProbeScore /
	// actor.journalProbeScore from the event mix and attempt rate.
	ProbeScore int
	Notes      string
}

type ActorUser struct {
	ActorID  string
	Username string
	Count    int
}

// IPStat is a per-IP roll-up for one actor (count + observation window).
// Produced by the actor builders so the persistence layer can avoid a
// second O(N) walk over events.
type IPStat struct {
	Count       int
	First, Last time.Time
}

// AggregatedActor pairs an Actor with the per-IP and per-username counts
// the builder already computed. The store consumes these directly.
type AggregatedActor struct {
	Actor *Actor
	IPs   map[string]IPStat
	Users map[string]int
}
