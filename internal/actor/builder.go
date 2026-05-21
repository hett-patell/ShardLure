package actor

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

type IPStats struct {
	Events     []*models.Event
	Users      map[string]int
	First, Last time.Time
}

type CowrieStats struct {
	Key       string
	PrimaryIP string
	HASSH     string
	Client    string
	Events    []*models.Event
	Users     map[string]int
	First     time.Time
	Last      time.Time
	Tunnel    bool
	Payload   bool
	Probe     bool
	DeployCmd bool
}

// BuildFromJournal groups journal events into actors (1 IP = 1 actor for journal mode).
func BuildFromJournal(events []*models.Event, adminIPs map[string]bool) ([]*models.Actor, map[string]string) {
	byIP := map[string]*IPStats{}
	eventToActor := map[string]string{} // key: raw line or composite   use index

	for _, e := range events {
		if e.Kind == models.KindAccepted {
			if adminIPs[e.SrcIP] {
				continue
			}
		}
		if e.SrcIP == "" {
			continue
		}
		st, ok := byIP[e.SrcIP]
		if !ok {
			st = &IPStats{Users: map[string]int{}}
			byIP[e.SrcIP] = st
		}
		st.Events = append(st.Events, e)
		if e.Username != "" && e.Username != "?" {
			st.Users[e.Username]++
		}
		if st.First.IsZero() || e.TS.Before(st.First) {
			st.First = e.TS
		}
		if e.TS.After(st.Last) {
			st.Last = e.TS
		}
	}

	var actors []*models.Actor
	for ip, st := range byIP {
		if len(st.Events) == 0 {
			continue
		}
		users := sortedKeys(st.Users)
		hours := st.Last.Sub(st.First).Hours()
		if hours < 0.25 {
			hours = 0.25
		}
		aph := float64(len(st.Events)) / hours

		uhash := usernameSetHash(users)
		id := fmt.Sprintf("journal:%s", ip)
		playbook := ClassifyPlaybook(users, aph)

		a := &models.Actor{
			ID:              id,
			Source:          models.SourceJournal,
			PrimaryIP:       ip,
			Playbook:        playbook,
			Intent:          "unknown",
			Confidence:      55,
			FirstSeen:       st.First,
			LastSeen:        st.Last,
			EventCount:      len(st.Events),
			UniqueUsers:     len(st.Users),
			AttemptsPerHour: aph,
			UsernameHash:    uhash,
			Notes:           fmt.Sprintf("%d distinct usernames", len(st.Users)),
		}
		if aph > 100 {
			a.Confidence = 70
		}
		actors = append(actors, a)
		for _, e := range st.Events {
			e.ActorID = id
		}
	}

	sort.Slice(actors, func(i, j int) bool {
		return actors[i].LastSeen.After(actors[j].LastSeen)
	})
	return actors, eventToActor
}

// BuildFromCowrie groups events by HASSH (fallback: source IP).
func BuildFromCowrie(events []*models.Event, adminIPs map[string]bool) ([]*models.Actor, map[string]string) {
	byKey := map[string]*CowrieStats{}
	eventToActor := map[string]string{}

	for _, e := range events {
		if e.SrcIP == "" {
			continue
		}
		if adminIPs[e.SrcIP] && e.Kind == models.KindAccepted {
			continue
		}
		key := e.HASSH
		if key == "" {
			key = e.SrcIP
		}
		st, ok := byKey[key]
		if !ok {
			st = &CowrieStats{
				Key:       key,
				PrimaryIP: e.SrcIP,
				HASSH:     e.HASSH,
				Client:    e.SSHClient,
				Users:     map[string]int{},
			}
			byKey[key] = st
		}
		st.Events = append(st.Events, e)
		if e.Username != "" && e.Username != "?" {
			st.Users[e.Username]++
		}
		if st.First.IsZero() || e.TS.Before(st.First) {
			st.First = e.TS
		}
		if e.TS.After(st.Last) {
			st.Last = e.TS
		}
		if st.PrimaryIP == "" {
			st.PrimaryIP = e.SrcIP
		}
		if st.HASSH == "" {
			st.HASSH = e.HASSH
		}
		if st.Client == "" {
			st.Client = e.SSHClient
		}
		if e.Kind == models.KindTunnel {
			st.Tunnel = true
		}
		if e.Kind == models.KindFileDown || e.Kind == models.KindFileUp || e.SHA256 != "" {
			st.Payload = true
		}
		if e.Kind == models.KindConnect || e.Kind == models.KindInvalidUser || e.Kind == models.KindFailedPass || e.Kind == models.KindFailedKey {
			st.Probe = true
		}
		if e.Kind == models.KindCommand {
			lc := strings.ToLower(e.Command)
			if strings.Contains(lc, "curl ") || strings.Contains(lc, "wget ") || strings.Contains(lc, "chmod +x") || strings.Contains(lc, "/tmp/") || strings.Contains(lc, "busybox") {
				st.DeployCmd = true
			}
		}
	}

	var actors []*models.Actor
	for _, st := range byKey {
		if len(st.Events) == 0 {
			continue
		}
		users := sortedKeys(st.Users)
		hours := st.Last.Sub(st.First).Hours()
		if hours < 0.25 {
			hours = 0.25
		}
		aph := float64(len(st.Events)) / hours
		uhash := usernameSetHash(users)
		intent := ClassifyIntent(st.Tunnel, st.Payload, st.Probe, st.DeployCmd)
		playbook := ClassifyPlaybook(users, aph)

		idSuffix := st.PrimaryIP
		if st.HASSH != "" {
			idSuffix = st.HASSH
		}
		id := fmt.Sprintf("cowrie:%s", idSuffix)
		a := &models.Actor{
			ID:              id,
			Source:          models.SourceCowrie,
			PrimaryIP:       st.PrimaryIP,
			Playbook:        playbook,
			Intent:          intent,
			Confidence:      72,
			FirstSeen:       st.First,
			LastSeen:        st.Last,
			EventCount:      len(st.Events),
			UniqueUsers:     len(st.Users),
			AttemptsPerHour: aph,
			HASSH:           st.HASSH,
			SSHClient:       st.Client,
			UsernameHash:    uhash,
			Notes:           fmt.Sprintf("%d events, %d usernames", len(st.Events), len(st.Users)),
		}
		if st.Payload || st.DeployCmd {
			a.Confidence = 84
		}
		actors = append(actors, a)
		for _, e := range st.Events {
			e.ActorID = id
		}
	}

	sort.Slice(actors, func(i, j int) bool {
		return actors[i].LastSeen.After(actors[j].LastSeen)
	})
	return actors, eventToActor
}

func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func usernameSetHash(users []string) string {
	if len(users) == 0 {
		return ""
	}
	sample := users
	if len(sample) > 40 {
		sample = sample[:40]
	}
	h := sha256.Sum256([]byte(strings.Join(sample, ",")))
	return hex.EncodeToString(h[:8])
}

func AdminSet(ips []string) map[string]bool {
	m := map[string]bool{}
	for _, ip := range ips {
		m[ip] = true
	}
	return m
}
