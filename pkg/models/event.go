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
	KindCommand     EventKind = "command"
	KindFileUp      EventKind = "file_upload"
	KindFileDown    EventKind = "file_download"
	KindTunnel      EventKind = "tunnel"
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
	JA4       string
	Command   string
	SHA256    string
	Filename  string
	Raw       string
	ActorID   string
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

type ActorIP struct {
	ActorID   string
	IP        string
	FirstSeen time.Time
	LastSeen  time.Time
	Count     int
}

type ActorUser struct {
	ActorID  string
	Username string
	Count    int
}
