package cowrie

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/networkshard/shardlure/internal/actor"
	"github.com/networkshard/shardlure/internal/store"
	"github.com/networkshard/shardlure/pkg/models"
)

type Result struct {
	Events  int
	Actors  int
	Skipped int
}

type cowrieLine struct {
	EventID     string `json:"eventid"`
	Timestamp   string `json:"timestamp"`
	SrcIP       string `json:"src_ip"`
	SrcPort     any    `json:"src_port"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	Session     string `json:"session"`
	HASSH       string `json:"hassh"`
	SSHVersion  string `json:"version"`
	Input       string `json:"input"`
	Message     string `json:"message"`
	URL         string `json:"url"`
	Filename    string `json:"filename"`
	DstPath     string `json:"destfile"`
	SHA256      string `json:"shasum"`
	Fingerprint string `json:"fingerprint"`
}

func IngestFile(st *store.Store, path string, adminIPs []string, replace bool) (*Result, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	events, skipped, _, err := parseReader(f)
	if err != nil {
		return nil, err
	}
	res, err := persistEvents(st, events, adminIPs, replace)
	if res != nil {
		res.Skipped = skipped
	}
	return res, err
}

func IngestFileAppend(st *store.Store, path string, adminIPs []string) (*Result, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Result{}, nil
		}
		return nil, err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	inode := fileInode(fi)

	prev, _, err := st.GetIngestState(models.SourceCowrie, path)
	if err != nil {
		return nil, err
	}

	// Reset offset if the file was rotated (different inode) or truncated.
	startOffset := prev.Offset
	if prev.Inode != inode || fi.Size() < startOffset {
		startOffset = 0
	}
	if _, err := f.Seek(startOffset, io.SeekStart); err != nil {
		return nil, err
	}

	events, skipped, consumed, err := parseReader(f)
	if err != nil {
		return nil, err
	}

	// Advance offset by exactly the bytes the scanner consumed, not by
	// fi.Size(): cowrie may have appended more bytes between Stat() and
	// EOF, and we don't want to claim those bytes were scanned.
	newOffset := startOffset + consumed
	if newOffset > fi.Size() {
		newOffset = fi.Size()
	}
	newState := store.IngestState{
		Source: models.SourceCowrie,
		Path:   path,
		Inode:  inode,
		Offset: newOffset,
	}

	var fresh []*models.Event
	for _, e := range events {
		exists, err := st.EventExists(e)
		if err != nil {
			return nil, err
		}
		if exists {
			continue
		}
		fresh = append(fresh, e)
	}
	if len(fresh) == 0 {
		if err := st.SetIngestState(newState); err != nil {
			return nil, err
		}
		return &Result{Skipped: skipped}, nil
	}
	all, err := st.EventsBySource(models.SourceCowrie)
	if err != nil {
		return nil, err
	}
	all = append(all, fresh...)
	res, err := syncCowrieActors(st, all, fresh, adminIPs)
	if res != nil {
		res.Skipped = skipped
	}
	if err != nil {
		return res, err
	}
	if err := st.SetIngestState(newState); err != nil {
		return res, err
	}
	return res, nil
}

func syncCowrieActors(st *store.Store, all, fresh []*models.Event, adminIPs []string) (*Result, error) {
	admin := actor.AdminSet(adminIPs)
	actors := actor.BuildFromCowrie(all, admin)
	if err := st.AppendEventsAndReplaceActors(models.SourceCowrie, fresh, all, actors); err != nil {
		return nil, err
	}
	return &Result{Events: len(all), Actors: len(actors)}, nil
}

func persistEvents(st *store.Store, events []*models.Event, adminIPs []string, replace bool) (*Result, error) {
	admin := actor.AdminSet(adminIPs)
	if replace {
		actors := actor.BuildFromCowrie(events, admin)
		if err := st.ReplaceSourceEventsAndActors(models.SourceCowrie, events, actors); err != nil {
			return nil, fmt.Errorf("persist cowrie events and actors: %w", err)
		}
		return &Result{Events: len(events), Actors: len(actors)}, nil
	}
	all, err := st.EventsBySource(models.SourceCowrie)
	if err != nil {
		return nil, err
	}
	all = append(all, events...)
	actors := actor.BuildFromCowrie(all, admin)
	if err := st.AppendEventsAndReplaceActors(models.SourceCowrie, events, all, actors); err != nil {
		return nil, fmt.Errorf("persist cowrie events and actors: %w", err)
	}
	return &Result{Events: len(all), Actors: len(actors)}, nil
}

// parseReader returns parsed events, the count of skipped/malformed lines,
// and the exact number of bytes consumed by the scanner. The byte count is
// used by IngestFileAppend to advance the persisted offset accurately,
// without skipping a partial line at the tail if the writer (cowrie) appended
// more data while we were reading.
func parseReader(r io.Reader) ([]*models.Event, int, int64, error) {
	var out []*models.Event
	var skipped int
	var consumed int64
	sc := bufio.NewScanner(r)
	buf := make([]byte, 0, 256*1024)
	sc.Buffer(buf, 2*1024*1024)
	for sc.Scan() {
		raw := sc.Bytes()
		// +1 for the line terminator the scanner already stripped.
		// (Last line may lack one; we don't advance the offset past EOF
		// so the extra +1 there is harmless — capped by the actual file size.)
		consumed += int64(len(raw)) + 1
		line := strings.TrimSpace(string(raw))
		if line == "" {
			continue
		}
		var rec cowrieLine
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			skipped++
			continue
		}
		e, ok := toEvent(rec, line)
		if !ok {
			skipped++
			continue
		}
		out = append(out, e)
	}
	if err := sc.Err(); err != nil {
		return nil, skipped, consumed, err
	}
	return out, skipped, consumed, nil
}

func toEvent(r cowrieLine, raw string) (*models.Event, bool) {
	if r.SrcIP == "" {
		return nil, false
	}
	kind, ok := mapKind(r.EventID)
	if !ok {
		return nil, false
	}
	ts, ok := parseTS(r.Timestamp)
	if !ok {
		return nil, false
	}
	srcPort := toInt(r.SrcPort)
	command := strings.TrimSpace(r.Input)
	if command == "" {
		command = strings.TrimSpace(r.Message)
	}
	filename := r.Filename
	if filename == "" {
		filename = r.DstPath
	}
	sshClient := r.SSHVersion
	if sshClient == "" {
		sshClient = r.Fingerprint
	}
	return &models.Event{
		TS:        ts,
		Source:    models.SourceCowrie,
		Kind:      kind,
		SrcIP:     r.SrcIP,
		SrcPort:   srcPort,
		Username:  r.Username,
		Password:  r.Password,
		SessionID: r.Session,
		HASSH:     r.HASSH,
		SSHClient: sshClient,
		Command:   command,
		SHA256:    strings.TrimSpace(r.SHA256),
		Filename:  filename,
		Raw:       raw,
	}, true
}

func mapKind(eventID string) (models.EventKind, bool) {
	switch eventID {
	case "cowrie.login.failed":
		return models.KindFailedPass, true
	case "cowrie.login.success":
		return models.KindAccepted, true
	case "cowrie.client.version", "cowrie.session.connect":
		return models.KindConnect, true
	case "cowrie.command.input":
		return models.KindCommand, true
	case "cowrie.session.file_upload":
		return models.KindFileUp, true
	case "cowrie.session.file_download":
		return models.KindFileDown, true
	case "cowrie.direct-tcpip.request", "cowrie.tunnel.local", "cowrie.tunnel.remote":
		return models.KindTunnel, true
	default:
		return "", false
	}
}

func parseTS(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	layouts := []string{
		time.RFC3339Nano,
		"2006-01-02T15:04:05.000000Z",
		"2006-01-02T15:04:05Z",
	}
	for _, l := range layouts {
		if t, err := time.Parse(l, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

func toInt(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case string:
		i, _ := strconv.Atoi(strings.TrimSpace(n))
		return i
	default:
		return 0
	}
}
