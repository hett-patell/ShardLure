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

	events, skipped, err := parseReader(f)
	if err != nil {
		return nil, err
	}
	if replace {
		if err := st.ClearBySource(models.SourceCowrie); err != nil {
			return nil, err
		}
	}
	res, err := persistEvents(st, events, adminIPs)
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

	events, skipped, err := parseReader(f)
	if err != nil {
		return nil, err
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
		return &Result{Skipped: skipped}, nil
	}
	for _, e := range fresh {
		if err := st.InsertEvent(e); err != nil {
			return nil, fmt.Errorf("insert event: %w", err)
		}
	}
	res, err := syncCowrieActors(st, adminIPs)
	if res != nil {
		res.Skipped = skipped
	}
	return res, err
}

func syncCowrieActors(st *store.Store, adminIPs []string) (*Result, error) {
	all, err := st.EventsBySource(models.SourceCowrie)
	if err != nil {
		return nil, err
	}
	admin := actor.AdminSet(adminIPs)
	actors, _ := actor.BuildFromCowrie(all, admin)
	if err := st.DeleteActorsBySource(models.SourceCowrie); err != nil {
		return nil, err
	}
	for _, a := range actors {
		if err := st.UpsertActor(a); err != nil {
			return nil, err
		}
		ipStats := map[string]int{}
		users := map[string]int{}
		for _, e := range all {
			if e.ActorID != a.ID {
				continue
			}
			if err := st.UpdateEventActor(e.ID, a.ID); err != nil {
				return nil, err
			}
			ipStats[e.SrcIP]++
			if e.Username != "" {
				users[e.Username]++
			}
		}
		for ip, c := range ipStats {
			if err := st.UpsertActorIP(a.ID, ip, a.FirstSeen, a.LastSeen, c); err != nil {
				return nil, err
			}
		}
		for u, c := range users {
			if err := st.UpsertActorUser(a.ID, u, c); err != nil {
				return nil, err
			}
		}
	}
	return &Result{Events: len(all), Actors: len(actors)}, nil
}

func persistEvents(st *store.Store, events []*models.Event, adminIPs []string) (*Result, error) {
	admin := actor.AdminSet(adminIPs)
	actors, _ := actor.BuildFromCowrie(events, admin)

	for _, e := range events {
		if err := st.InsertEvent(e); err != nil {
			return nil, fmt.Errorf("insert event: %w", err)
		}
	}
	for _, a := range actors {
		if err := st.UpsertActor(a); err != nil {
			return nil, err
		}
		ipStats := map[string]int{}
		users := map[string]int{}
		for _, e := range events {
			if e.ActorID != a.ID {
				continue
			}
			ipStats[e.SrcIP]++
			if e.Username != "" {
				users[e.Username]++
			}
		}
		for ip, c := range ipStats {
			if err := st.UpsertActorIP(a.ID, ip, a.FirstSeen, a.LastSeen, c); err != nil {
				return nil, err
			}
		}
		for u, c := range users {
			if err := st.UpsertActorUser(a.ID, u, c); err != nil {
				return nil, err
			}
		}
	}
	return &Result{Events: len(events), Actors: len(actors)}, nil
}

func parseReader(r io.Reader) ([]*models.Event, int, error) {
	var out []*models.Event
	var skipped int
	sc := bufio.NewScanner(r)
	buf := make([]byte, 0, 256*1024)
	sc.Buffer(buf, 2*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
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
		return nil, skipped, err
	}
	return out, skipped, nil
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
