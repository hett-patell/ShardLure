package actor

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

type IPStats struct {
	Events      []*models.Event
	Users       map[string]int
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

func JournalActorID(ip string) string {
	return fmt.Sprintf("journal:%s", ip)
}

// Confidence scores are 0-100.
const (
	ConfidenceJournalBase    = 55
	ConfidenceJournalHighAPH = 70
	ConfidenceCowrieBase     = 72
	ConfidenceCowriePayload  = 84
)

// BuildFromJournal groups journal events into actors (1 IP = 1 actor for journal mode).
func BuildFromJournal(events []*models.Event, adminIPs map[string]bool) []*models.Actor {
	byIP := map[string]*IPStats{}

	for _, e := range events {
		if adminIPs[e.SrcIP] {
			// Never classify known admin sources as attackers.
			continue
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
		id := JournalActorID(ip)
		playbook := ClassifyPlaybook(users, aph)

		a := &models.Actor{
			ID:              id,
			Source:          models.SourceJournal,
			PrimaryIP:       ip,
			Playbook:        playbook,
			Intent:          "unknown",
			Confidence:      ConfidenceJournalBase,
			FirstSeen:       st.First,
			LastSeen:        st.Last,
			EventCount:      len(st.Events),
			UniqueUsers:     len(st.Users),
			AttemptsPerHour: aph,
			UsernameHash:    uhash,
			ProbeScore:      journalProbeScore(len(st.Events), aph, len(st.Users)),
			Notes:           fmt.Sprintf("%d distinct usernames", len(st.Users)),
		}
		if st.Last.Sub(st.First).Hours() >= 0.25 && aph > 100 {
			a.Confidence = ConfidenceJournalHighAPH
		}
		actors = append(actors, a)
		for _, e := range st.Events {
			e.ActorID = id
		}
	}

	sort.Slice(actors, func(i, j int) bool {
		return actors[i].LastSeen.After(actors[j].LastSeen)
	})
	return actors
}

// BuildFromCowrie groups events by HASSH (fallback: source IP).
func BuildFromCowrie(events []*models.Event, adminIPs map[string]bool) []*models.Actor {
	byKey := map[string]*CowrieStats{}

	for _, e := range events {
		if e.SrcIP == "" {
			continue
		}
		if adminIPs[e.SrcIP] {
			// Keep admin traffic out of attacker clustering in all cases.
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
			Confidence:      ConfidenceCowrieBase,
			FirstSeen:       st.First,
			LastSeen:        st.Last,
			EventCount:      len(st.Events),
			UniqueUsers:     len(st.Users),
			AttemptsPerHour: aph,
			HASSH:           st.HASSH,
			SSHClient:       st.Client,
			UsernameHash:    uhash,
			ProbeScore:      cowrieProbeScore(st, aph),
			Notes:           fmt.Sprintf("%d events, %d usernames", len(st.Events), len(st.Users)),
		}
		if st.Payload || st.DeployCmd {
			a.Confidence = ConfidenceCowriePayload
		}
		actors = append(actors, a)
		for _, e := range st.Events {
			e.ActorID = id
		}
	}

	sort.Slice(actors, func(i, j int) bool {
		return actors[i].LastSeen.After(actors[j].LastSeen)
	})
	return actors
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
	h := sha256.New()
	for i, u := range users {
		if i > 0 {
			_, _ = io.WriteString(h, ",")
		}
		_, _ = io.WriteString(h, u)
	}
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:8])
}

func AdminSet(ips []string) map[string]bool {
	m := map[string]bool{}
	for _, ip := range ips {
		m[ip] = true
	}
	return m
}

// cowrieProbeScore returns a 0-100 score combining the boolean event-type
// signals we already detect during clustering with the per-hour attempt rate.
// Higher = more confidently a probe/recon actor. Used to populate
// Actor.ProbeScore which the dashboard and IOC export can sort on.
func cowrieProbeScore(st *CowrieStats, aph float64) int {
	score := 0
	if st.Probe {
		score += 40
	}
	if st.Tunnel {
		score += 15
	}
	if st.Payload {
		score += 25
	}
	if st.DeployCmd {
		score += 25
	}
	switch {
	case aph >= 120:
		score += 20
	case aph >= 60:
		score += 12
	case aph >= 20:
		score += 6
	}
	if score > 100 {
		score = 100
	}
	return score
}

// journalProbeScore is the journal-source analogue. We only have failed-auth
// signals there, so the score is mostly rate-driven.
func journalProbeScore(eventCount int, aph float64, uniqueUsers int) int {
	score := 30 // any failed-auth volume on the bait port is probe-like by default
	switch {
	case aph >= 120:
		score += 35
	case aph >= 60:
		score += 22
	case aph >= 20:
		score += 12
	}
	if uniqueUsers >= 10 {
		score += 20
	} else if uniqueUsers >= 3 {
		score += 10
	}
	if eventCount >= 100 {
		score += 10
	}
	if score > 100 {
		score = 100
	}
	return score
}
