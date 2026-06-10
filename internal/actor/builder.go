package actor

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/networkshard/shardlure/internal/netmatch"
	"github.com/networkshard/shardlure/pkg/models"
)

// IPStats is the per-IP roll-up used during journal clustering. It used to
// hold every event pointer for the IP; we now keep counts only, which is
// what the classifier actually needs and avoids retaining O(N) event
// pointers in memory during ingest.
type IPStats struct {
	Count       int
	Users       map[string]int
	First, Last time.Time
}

type CowrieStats struct {
	Key       string
	PrimaryIP string
	HASSH     string
	Client    string
	// IPs maps src_ip to per-IP roll-up (cowrie actors are keyed by HASSH
	// and can span multiple source IPs).
	IPs       map[string]IPStat
	Count     int
	Users     map[string]int
	First     time.Time
	Last      time.Time
	Tunnel    bool
	Payload   bool
	Probe     bool
	DeployCmd bool
}

// AggregatedActor and IPStat live in pkg/models so the store package can
// consume them without importing internal/actor (which would create a cycle:
// actor/sync.go already imports store).
type AggregatedActor = models.AggregatedActor
type IPStat = models.IPStat

func JournalActorID(ip string) string {
	return fmt.Sprintf("journal:%s", ip)
}

// TrimActorPrefix strips the source prefix from an actor ID for display.
// Both "journal:" and "cowrie:" prefixes are removed; unknown formats are
// returned unchanged. Centralised here to avoid the same six lines being
// repeated in main.go, web/server.go, web/intel.go.
func TrimActorPrefix(id string) string {
	if i := strings.IndexByte(id, ':'); i >= 0 {
		switch id[:i] {
		case "journal", "cowrie":
			return id[i+1:]
		}
	}
	return id
}

// CowrieActorID returns the actor ID a cowrie event would be assigned to,
// without running the full builder. Used by the ingest path to stamp
// e.ActorID on fresh events before INSERT (the streaming collector no
// longer retains the event pointer, so it can't mutate it itself).
func CowrieActorID(srcIP, hassh string) string {
	suffix := srcIP
	if hassh != "" {
		suffix = hassh
	}
	return "cowrie:" + suffix
}

// AssignJournalActorIDs stamps ActorID on every non-admin journal event in
// the slice. Admin events are intentionally left blank so the join in the
// dashboard never associates real operators with an attacker actor.
func AssignJournalActorIDs(events []*models.Event, adminIPs *netmatch.Set) {
	for _, e := range events {
		if e == nil || e.SrcIP == "" || adminIPs.Has(e.SrcIP) {
			continue
		}
		e.ActorID = JournalActorID(e.SrcIP)
	}
}

// AssignCowrieActorIDs is the cowrie analogue of AssignJournalActorIDs.
func AssignCowrieActorIDs(events []*models.Event, adminIPs *netmatch.Set) {
	for _, e := range events {
		if e == nil || e.SrcIP == "" || adminIPs.Has(e.SrcIP) {
			continue
		}
		e.ActorID = CowrieActorID(e.SrcIP, e.HASSH)
	}
}

// Confidence scores are 0-100.
const (
	ConfidenceJournalBase    = 55
	ConfidenceJournalHighAPH = 70
	ConfidenceCowrieBase     = 72
	ConfidenceCowriePayload  = 84
)

// minWindowHours floors the observation window when computing attempts/hour
// so a single burst of activity inside one minute does not produce a divide
// near zero (and a meaningless 100k/hour rate). 15 minutes is empirically
// the smallest window where rate carries information for our classifier.
const minWindowHours = 0.25

// BuildFromJournal groups journal events into actors (1 IP = 1 actor for journal mode).
func BuildFromJournal(events []*models.Event, adminIPs *netmatch.Set) []*models.Actor {
	agg := BuildFromJournalAggregated(events, adminIPs)
	out := make([]*models.Actor, 0, len(agg))
	for _, a := range agg {
		out = append(out, a.Actor)
	}
	return out
}

// BuildFromJournalAggregated returns actors with the per-IP and per-user
// stats the builder already computed so the persistence layer does not need
// to scan events a second time.
func BuildFromJournalAggregated(events []*models.Event, adminIPs *netmatch.Set) []*AggregatedActor {
	jc := newJournalCollector(adminIPs)
	for _, e := range events {
		jc.add(e)
	}
	return jc.finalize()
}

// BuildJournalActorsStreaming pushes journal events through the same logic
// as BuildFromJournalAggregated without requiring them in a slice. The
// caller passes a function that, when invoked, yields the next event or
// (nil, io.EOF) when done. Used by the ingest path so we don't materialize
// every persisted journal event in memory just to recompute actors.
func BuildJournalActorsStreaming(next func() (*models.Event, error), adminIPs *netmatch.Set) ([]*AggregatedActor, error) {
	jc := newJournalCollector(adminIPs)
	for {
		e, err := next()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		if e == nil {
			break
		}
		jc.add(e)
	}
	return jc.finalize(), nil
}

// JournalCollector is the streaming equivalent of BuildFromJournalAggregated.
// See CowrieCollector for usage.
type JournalCollector = journalCollector

type journalCollector struct {
	admin *netmatch.Set
	byIP  map[string]*IPStats
}

func NewJournalCollector(adminIPs *netmatch.Set) *JournalCollector {
	return newJournalCollector(adminIPs)
}

func newJournalCollector(adminIPs *netmatch.Set) *journalCollector {
	return &journalCollector{admin: adminIPs, byIP: map[string]*IPStats{}}
}

// Add is the exported wrapper around add().
func (c *journalCollector) Add(e *models.Event) { c.add(e) }

// Finalize is the exported wrapper around finalize().
func (c *journalCollector) Finalize() []*AggregatedActor { return c.finalize() }

// FinalizeIP returns the current AggregatedActor for a single IP
// without iterating the whole byIP map. Returns nil if the IP has
// been filtered out (admin) or has no recorded events yet. Used by
// the live journal tail so each new event triggers a per-IP actor
// upsert instead of a full rebuild.
//
// Cost: O(U log U) where U is the unique-username count for that IP
// (the sort in sortedKeys + the map copy). For typical journal
// traffic U stays in single digits; even a spray with 1000 distinct
// usernames is sub-millisecond per event. The previous comment
// claimed O(1) amortised, which was wrong - it's O(1) for counter
// updates in add(), but FinalizeIP itself is O(U).
func (c *journalCollector) FinalizeIP(ip string) *AggregatedActor {
	st, ok := c.byIP[ip]
	if !ok || st.Count == 0 {
		return nil
	}
	// copyUsers=true: FinalizeIP can be called many times against
	// the same live collector, so the returned aggregator must not
	// alias the collector's internal map.
	return buildJournalActor(ip, st, true)
}

func (c *journalCollector) add(e *models.Event) {
	if e == nil || e.SrcIP == "" || c.admin.Has(e.SrcIP) {
		return
	}
	st, ok := c.byIP[e.SrcIP]
	if !ok {
		st = &IPStats{Users: map[string]int{}}
		c.byIP[e.SrcIP] = st
	}
	st.Count++
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

func (c *journalCollector) finalize() []*AggregatedActor {
	var actors []*AggregatedActor
	for ip, st := range c.byIP {
		if st.Count == 0 {
			continue
		}
		// copyUsers=false: the bulk finalize() path discards the
		// collector immediately after, so we can hand the user map
		// off by reference without aliasing hazards.
		actors = append(actors, buildJournalActor(ip, st, false))
	}
	sort.Slice(actors, func(i, j int) bool {
		return actors[i].Actor.LastSeen.After(actors[j].Actor.LastSeen)
	})
	return actors
}

// buildJournalActor constructs the AggregatedActor for a single
// (ip, stats) pair using the journal scoring rules. Shared by both
// the bulk finalize() (collector-then-discard) and the incremental
// FinalizeIP (collector-lives-on) paths.
//
// copyUsers controls aliasing: pass true when the returned actor's
// Users map must not share storage with st.Users (i.e. the collector
// will keep mutating st after we return). Pass false when the
// collector is about to be discarded.
func buildJournalActor(ip string, st *IPStats, copyUsers bool) *AggregatedActor {
	users := sortedKeys(st.Users)
	hours := st.Last.Sub(st.First).Hours()
	if hours < minWindowHours {
		hours = minWindowHours
	}
	aph := float64(st.Count) / hours

	a := &models.Actor{
		ID:              JournalActorID(ip),
		Source:          models.SourceJournal,
		PrimaryIP:       ip,
		Playbook:        ClassifyPlaybook(users, aph),
		Intent:          "unknown",
		Confidence:      ConfidenceJournalBase,
		FirstSeen:       st.First,
		LastSeen:        st.Last,
		EventCount:      st.Count,
		UniqueUsers:     len(st.Users),
		AttemptsPerHour: aph,
		UsernameHash:    usernameSetHash(users),
		ProbeScore:      journalProbeScore(st.Count, aph, len(st.Users)),
		Notes:           fmt.Sprintf("%d distinct usernames", len(st.Users)),
	}
	if st.Last.Sub(st.First).Hours() >= minWindowHours && aph > 100 {
		a.Confidence = ConfidenceJournalHighAPH
	}
	ips := map[string]IPStat{
		ip: {Count: st.Count, First: st.First, Last: st.Last},
	}
	usersOut := st.Users
	if copyUsers {
		usersOut = make(map[string]int, len(st.Users))
		for k, v := range st.Users {
			usersOut[k] = v
		}
	}
	return &AggregatedActor{Actor: a, IPs: ips, Users: usersOut}
}

// BuildFromCowrie groups events by HASSH (fallback: source IP).
func BuildFromCowrie(events []*models.Event, adminIPs *netmatch.Set) []*models.Actor {
	agg := BuildFromCowrieAggregated(events, adminIPs)
	out := make([]*models.Actor, 0, len(agg))
	for _, a := range agg {
		out = append(out, a.Actor)
	}
	return out
}

// BuildFromCowrieAggregated mirrors BuildFromCowrie but returns the per-IP
// and per-user stats the builder already computed so the persistence layer
// does not need to re-walk events. See writeActorsTx.
func BuildFromCowrieAggregated(events []*models.Event, adminIPs *netmatch.Set) []*AggregatedActor {
	cc := newCowrieCollector(adminIPs)
	for _, e := range events {
		cc.add(e)
	}
	return cc.finalize()
}

// BuildCowrieActorsStreaming is the streaming analogue of
// BuildFromCowrieAggregated. See BuildJournalActorsStreaming for the
// memory rationale.
func BuildCowrieActorsStreaming(next func() (*models.Event, error), adminIPs *netmatch.Set) ([]*AggregatedActor, error) {
	cc := newCowrieCollector(adminIPs)
	for {
		e, err := next()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		if e == nil {
			break
		}
		cc.add(e)
	}
	return cc.finalize(), nil
}

// CowrieCollector incrementally feeds events into the cowrie clustering
// logic. Use this to avoid materializing every persisted event in memory:
//
//	c := actor.NewCowrieCollector(admin)
//	st.IterateEventsBySource(SourceCowrie, func(e *models.Event) error { c.Add(e); return nil })
//	for _, e := range fresh { c.Add(e) }
//	actors := c.Finalize()
type CowrieCollector = cowrieCollector

type cowrieCollector struct {
	admin *netmatch.Set
	byKey map[string]*CowrieStats
}

func NewCowrieCollector(adminIPs *netmatch.Set) *CowrieCollector {
	return newCowrieCollector(adminIPs)
}

func newCowrieCollector(adminIPs *netmatch.Set) *cowrieCollector {
	return &cowrieCollector{admin: adminIPs, byKey: map[string]*CowrieStats{}}
}

// Add is the exported wrapper around add().
func (c *cowrieCollector) Add(e *models.Event) { c.add(e) }

// Finalize is the exported wrapper around finalize().
func (c *cowrieCollector) Finalize() []*AggregatedActor { return c.finalize() }

func (c *cowrieCollector) add(e *models.Event) {
	if e == nil || e.SrcIP == "" || c.admin.Has(e.SrcIP) {
		return
	}
	key := e.HASSH
	if key == "" {
		key = e.SrcIP
	}
	st, ok := c.byKey[key]
	if !ok {
		st = &CowrieStats{
			Key:       key,
			PrimaryIP: e.SrcIP,
			HASSH:     e.HASSH,
			Client:    e.SSHClient,
			IPs:       map[string]IPStat{},
			Users:     map[string]int{},
		}
		c.byKey[key] = st
	}
	st.Count++
	if e.Username != "" && e.Username != "?" {
		st.Users[e.Username]++
	}
	if st.First.IsZero() || e.TS.Before(st.First) {
		st.First = e.TS
	}
	if e.TS.After(st.Last) {
		st.Last = e.TS
	}
	// Per-IP roll-up.
	ip := st.IPs[e.SrcIP]
	ip.Count++
	if ip.First.IsZero() || e.TS.Before(ip.First) {
		ip.First = e.TS
	}
	if e.TS.After(ip.Last) {
		ip.Last = e.TS
	}
	st.IPs[e.SrcIP] = ip

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
		if looksLikeDeployCmd(e.Command) {
			st.DeployCmd = true
		}
	}
}

func (c *cowrieCollector) finalize() []*AggregatedActor {
	var actors []*AggregatedActor
	for _, st := range c.byKey {
		if st.Count == 0 {
			continue
		}
		users := sortedKeys(st.Users)
		hours := st.Last.Sub(st.First).Hours()
		if hours < minWindowHours {
			hours = minWindowHours
		}
		aph := float64(st.Count) / hours
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
			EventCount:      st.Count,
			UniqueUsers:     len(st.Users),
			AttemptsPerHour: aph,
			HASSH:           st.HASSH,
			SSHClient:       st.Client,
			UsernameHash:    uhash,
			ProbeScore:      cowrieProbeScore(st, aph),
			Notes:           fmt.Sprintf("%d events, %d usernames", st.Count, len(st.Users)),
		}
		if st.Payload || st.DeployCmd {
			a.Confidence = ConfidenceCowriePayload
		}
		actors = append(actors, &AggregatedActor{Actor: a, IPs: st.IPs, Users: st.Users})
	}
	sort.Slice(actors, func(i, j int) bool {
		return actors[i].Actor.LastSeen.After(actors[j].Actor.LastSeen)
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

// AdminSet builds the matcher used to exempt operator/trusted addresses from
// actor clustering. Entries may be bare IPs or CIDR ranges (e.g. a Tailscale
// CGNAT range "100.64.0.0/10"); see internal/netmatch.
func AdminSet(ips []string) *netmatch.Set {
	return netmatch.New(ips)
}

// looksLikeDeployCmd reports whether a shell command shows "curl-bash-into-tmp"
// deploy energy: a fetch-and-stage pattern, not merely a passing mention of a
// downloader word or /tmp. The previous heuristic flagged any command
// containing "/tmp/" (so a benign `ls /tmp/` scored as deploy) or a bare
// "curl " substring. We now require either:
//   - a downloader (curl/wget/tftp/fetch) AND a sink (pipe to a shell, a write
//     redirect, an -O/-o output file, or a /tmp path), or
//   - an explicit make-executable / run-from-tmp action (chmod +x, ./payload,
//     busybox wget, sh /tmp/...).
// This is heuristic confidence scoring only, so over- vs under-matching just
// nudges ProbeScore — but tightening it keeps recon sessions from masquerading
// as deploys in the dashboard's "spicy ones" view.
func looksLikeDeployCmd(cmd string) bool {
	lc := strings.ToLower(cmd)
	hasDownloader := strings.Contains(lc, "curl ") ||
		strings.Contains(lc, "wget ") ||
		strings.Contains(lc, "wget;") ||
		strings.Contains(lc, "tftp ") ||
		strings.Contains(lc, "busybox wget") ||
		strings.Contains(lc, "busybox tftp")
	// NOTE: deliberately no "-o" output-flag signal — it's too ambiguous
	// (matches `ssh -o StrictHostKeyChecking=no`). A real curl/wget-to-disk
	// dropper is already caught by the pipe-to-shell, redirect, or /tmp/ sinks.
	hasSink := strings.Contains(lc, "|sh") || strings.Contains(lc, "| sh") ||
		strings.Contains(lc, "|bash") || strings.Contains(lc, "| bash") ||
		strings.Contains(lc, ">") || // redirect to a file
		strings.Contains(lc, "/tmp/")
	if hasDownloader && hasSink {
		return true
	}
	// Stage/execute signatures that imply a payload is being run regardless
	// of how it arrived (e.g. dropped via SFTP, then executed).
	if strings.Contains(lc, "chmod +x") || strings.Contains(lc, "chmod 777") {
		return true
	}
	// Executing a dropped binary from cwd: "./payload" or "; ./payload". Only
	// count "./" when it's the START of a command token (line start or after a
	// shell separator) — otherwise "cd ./subdir" and other relative-path
	// arguments produce false positives.
	if isExecFromCwd(lc) {
		return true
	}
	if strings.Contains(lc, "/tmp/") &&
		(strings.Contains(lc, "sh ") || strings.Contains(lc, "bash ") || strings.Contains(lc, "exec ")) {
		return true
	}
	return false
}

// isExecFromCwd reports whether lc invokes a binary from the current directory
// ("./foo") as a command — i.e. "./" appears at the start of a command token
// (string start or right after a shell command separator), not merely as part
// of a path argument like "cd ./subdir" or "cat ./file".
func isExecFromCwd(lc string) bool {
	for i := 0; i+1 < len(lc); i++ {
		if lc[i] != '.' || lc[i+1] != '/' {
			continue
		}
		if i == 0 {
			return true
		}
		// Walk back over spaces to the preceding non-space char; it must be a
		// command separator for "./" to be a command start.
		j := i - 1
		for j >= 0 && lc[j] == ' ' {
			j--
		}
		if j < 0 {
			return true
		}
		switch lc[j] {
		case ';', '&', '|', '(', '`':
			return true
		}
	}
	return false
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
