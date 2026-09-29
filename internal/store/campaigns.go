package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
)

type EvidenceRow struct {
	Kind, Value, Label, SessionID, ActorID, IP string
	FirstSeen, LastSeen                        time.Time
	SizeBytes                                  int64 // -1 when no artifact row
}

type ScriptOccRow struct {
	Fingerprint, SessionID, ActorID, IP string
	FirstSeen, LastSeen                 time.Time
	Distinctive                         bool
}

type CampaignAssignmentRow struct {
	Kind, Value, CampaignID string
	Seq                     int64
}

type CampaignEditRow struct {
	ID                           int64
	CampaignID, Action, Arg, Who string
	CreatedAt                    time.Time
}

type CampaignMemberRow struct {
	ActorID       string
	Sessions, IPs int
	Reasons       string // JSON
}

type CampaignRow struct {
	ID, AnchorKind, AnchorValue, SuggestedName, Name, Notes, Kinds, Search string
	FirstSeen, LastSeen                                                    time.Time
	Actors, IPs, Sessions                                                  int
	Members                                                                []CampaignMemberRow
}

type CampaignSummary struct {
	ID, Name, SuggestedName string
	Actors, IPs, Sessions   int
	FirstSeen, LastSeen     time.Time
	Kinds                   []string
	Search                  string
}

type CampaignMemberDetail struct {
	ActorID, PrimaryIP, Playbook string
	Sessions, IPs                int
	Reasons                      string
}

// CampaignDetail lists at most campaignDetailCap members, HASSHes, clients
// and hosts; the *Total fields are the true counts, so a caller can tell a
// truncated list from a complete one.
type CampaignDetail struct {
	CampaignSummary
	Notes, AnchorKind, AnchorValue                       string
	Members                                              []CampaignMemberDetail
	HASSHes, Clients, Hosts                              []string
	MembersTotal, HASSHesTotal, ClientsTotal, HostsTotal int
	Edits                                                []CampaignEditRow
}

// campaignDetailCap bounds each list in a campaign detail. A campaign's
// membership is attacker-driven (the Outlaw/Dota component on prod holds 534
// IPs), and every detail request would otherwise return and render all of
// it. A var so tests can shrink it.
var campaignDetailCap = 500

type ScriptFamilyRow struct {
	Family, Display, Variants, Reason   string // Variants is JSON
	Sessions, Actors, IPs, CommandCount int
	Distinctive, Links                  bool
	FirstSeen, LastSeen                 time.Time
}

type ScriptSession struct {
	SessionID, ActorID, SrcIP string
	FirstSeen                 time.Time
}

type ScriptDetail struct {
	Fingerprint, Display, Family string
	Sessions                     []ScriptSession
	Actors                       []string
}

var ErrStaleGrouping = errors.New("store: campaign edits changed during grouping")

// ErrAmbiguousCampaign matches (errors.Is) the *AmbiguousCampaignError
// GetCampaign returns when a name or suggested name matches more than one
// campaign (several "Outlaw/Dota" components are normal). Callers must ask
// for the ID; picking one would silently show the operator a different
// campaign from the one they meant.
var ErrAmbiguousCampaign = errors.New("store: campaign name is ambiguous")

// AmbiguousCampaignError carries every matching campaign ID, sorted, so the
// caller can offer them instead of only refusing. The IDs come from the same
// query that detected the ambiguity (SQLite's ASCII lower() on name and
// suggested name), uncapped: a truncated list would hide the one the
// operator wants.
type AmbiguousCampaignError struct {
	Name string
	IDs  []string
}

func (e *AmbiguousCampaignError) Error() string {
	return fmt.Sprintf("%v: %q matches %d campaigns (%s)", ErrAmbiguousCampaign, e.Name, len(e.IDs), strings.Join(e.IDs, ", "))
}

// Is makes errors.Is(err, ErrAmbiguousCampaign) hold.
func (e *AmbiguousCampaignError) Is(target error) bool { return target == ErrAmbiguousCampaign }

// ErrInvalidGrouping rejects a grouping carrying an empty or duplicate
// identifier. An assignment whose campaign ID is "" is fed back into the next
// run and makes it emit a campaign whose ID is "", so nothing empty is ever
// persisted. Duplicates (a (kind, value) assigned twice, a campaign ID or a
// member listed twice) are caught here rather than as a primary-key failure
// halfway through the replace: Group emits each once, so a duplicate is an
// upstream bug and must read as one, not as an I/O error.
var ErrInvalidGrouping = errors.New("store: campaign grouping has an empty or duplicate identifier")

func validateGrouping(rows []CampaignRow, assign []CampaignAssignmentRow, aliases map[string]string) error {
	ids := make(map[string]bool, len(rows))
	for _, c := range rows {
		if c.ID == "" {
			return fmt.Errorf("%w: campaign row", ErrInvalidGrouping)
		}
		if ids[c.ID] {
			return fmt.Errorf("%w: campaign %s listed twice", ErrInvalidGrouping, c.ID)
		}
		ids[c.ID] = true
		members := make(map[string]bool, len(c.Members))
		for _, m := range c.Members {
			if m.ActorID == "" {
				return fmt.Errorf("%w: member of %s", ErrInvalidGrouping, c.ID)
			}
			if members[m.ActorID] {
				return fmt.Errorf("%w: member %s of %s listed twice", ErrInvalidGrouping, m.ActorID, c.ID)
			}
			members[m.ActorID] = true
		}
	}
	type key struct{ kind, value string }
	seen := make(map[key]bool, len(assign))
	for _, a := range assign {
		if a.Kind == "" || a.Value == "" || a.CampaignID == "" {
			return fmt.Errorf("%w: assignment %s", ErrInvalidGrouping, a.Kind)
		}
		k := key{a.Kind, a.Value}
		if seen[k] {
			return fmt.Errorf("%w: %s value assigned twice", ErrInvalidGrouping, a.Kind)
		}
		seen[k] = true
	}
	for o, n := range aliases {
		if o == "" || n == "" {
			return fmt.Errorf("%w: alias %q -> %q", ErrInvalidGrouping, o, n)
		}
	}
	return nil
}

func parseCampaignTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

func fmtCampaignTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return formatFixedUTC(t)
}

func (s *Store) CampaignEvidenceRows(ctx context.Context) ([]EvidenceRow, error) {
	if err := s.ensureArtifactsTable(); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT e.kind, e.value, e.label, e.session_id, e.actor_id, e.src_ip, e.first_seen, e.last_seen, COALESCE(a.size, -1)
FROM campaign_evidence e LEFT JOIN (SELECT sha256, MAX(size_bytes) AS size FROM artifacts GROUP BY sha256) a ON e.kind='payload' AND a.sha256=e.value
WHERE e.actor_id<>'' ORDER BY e.kind, e.value, e.session_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EvidenceRow
	for rows.Next() {
		var r EvidenceRow
		var f, l string
		if err := rows.Scan(&r.Kind, &r.Value, &r.Label, &r.SessionID, &r.ActorID, &r.IP, &f, &l, &r.SizeBytes); err != nil {
			return nil, err
		}
		r.FirstSeen, r.LastSeen = parseCampaignTime(f), parseCampaignTime(l)
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) SettledScriptRows(ctx context.Context) ([]ScriptOccRow, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT ss.fingerprint, ss.session_id, ss.actor_id, ss.src_ip, ss.first_seen, ss.last_seen, sc.distinctive
FROM session_scripts ss JOIN scripts sc ON sc.fingerprint=ss.fingerprint
WHERE ss.fingerprint<>'' AND ss.actor_id<>'' ORDER BY ss.fingerprint, ss.session_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ScriptOccRow
	for rows.Next() {
		var r ScriptOccRow
		var f, l string
		var d int
		if err := rows.Scan(&r.Fingerprint, &r.SessionID, &r.ActorID, &r.IP, &f, &l, &d); err != nil {
			return nil, err
		}
		r.FirstSeen, r.LastSeen, r.Distinctive = parseCampaignTime(f), parseCampaignTime(l), d == 1
		out = append(out, r)
	}
	return out, rows.Err()
}

// CowrieActorPopulation counts Cowrie actors seen since `since` (zero: all).
// actors.last_seen is fixed-width formatFixedUTC text, so the bound uses the
// same format and the string comparison is exact.
func (s *Store) CowrieActorPopulation(ctx context.Context, since time.Time) (int, error) {
	var n int
	var err error
	if since.IsZero() {
		err = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM actors WHERE source='cowrie'`).Scan(&n)
	} else {
		err = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM actors WHERE source='cowrie' AND last_seen >= ?`, formatFixedUTC(since)).Scan(&n)
	}
	return n, err
}

// CampaignIdentity returns the persisted assignments and aliases that feed
// the next grouping. Rows with an empty ID are skipped: SaveGrouping never
// writes them, and one fed back would make the grouping emit campaign "".
func (s *Store) CampaignIdentity(ctx context.Context) ([]CampaignAssignmentRow, map[string]string, error) {
	assign, err := s.campaignAssignments(ctx)
	if err != nil {
		return nil, nil, err
	}
	aliases, err := s.CampaignAliases(ctx)
	if err != nil {
		return nil, nil, err
	}
	return assign, aliases, nil
}

// CampaignAliases returns only the alias map (old ID -> newer ID). Request
// paths resolve IDs through it without loading every campaign_ids row, which
// grows with every distinct evidence value ever assigned.
func (s *Store) CampaignAliases(ctx context.Context) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT old_id, new_id FROM campaign_aliases WHERE old_id<>'' AND new_id<>''`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	aliases := map[string]string{}
	for rows.Next() {
		var o, n string
		if err := rows.Scan(&o, &n); err != nil {
			return nil, err
		}
		aliases[o] = n
	}
	return aliases, rows.Err()
}

func (s *Store) campaignAssignments(ctx context.Context) ([]CampaignAssignmentRow, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT kind, value, campaign_id, seq FROM campaign_ids
WHERE campaign_id<>'' AND kind<>'' AND value<>'' ORDER BY seq`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var assign []CampaignAssignmentRow
	for rows.Next() {
		var a CampaignAssignmentRow
		if err := rows.Scan(&a.Kind, &a.Value, &a.CampaignID, &a.Seq); err != nil {
			return nil, err
		}
		assign = append(assign, a)
	}
	return assign, rows.Err()
}

func (s *Store) CampaignEdits(ctx context.Context) ([]CampaignEditRow, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, campaign_id, action, arg, who, created_at FROM campaign_edits ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CampaignEditRow
	for rows.Next() {
		var r CampaignEditRow
		var at string
		if err := rows.Scan(&r.ID, &r.CampaignID, &r.Action, &r.Arg, &r.Who, &at); err != nil {
			return nil, err
		}
		r.CreatedAt = parseCampaignTime(at)
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) AppendCampaignEdit(ctx context.Context, campaignID, action, arg, who string) error {
	return s.WithTxContext(ctx, func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO campaign_edits(campaign_id,action,arg,who,created_at) VALUES(?,?,?,?,?)`,
			campaignID, action, arg, who, formatFixedUTC(time.Now()))
		return err
	})
}

// CampaignHasMember reports whether actorID is a stored member of any of ids,
// each first followed through the stored aliases to the campaign it currently
// shows as (the same resolution ResolveCampaignID applies for existence). An
// actor sits in few campaigns, so this reads the actor's memberships through
// idx_campaign_members_actor and matches them in Go.
func (s *Store) CampaignHasMember(ctx context.Context, ids []string, actorID string) (bool, error) {
	aliases, err := s.CampaignAliases(ctx)
	if err != nil {
		return false, err
	}
	want := make(map[string]bool, len(ids))
	for _, id := range ids {
		want[campaignAliasTarget(aliases, id)] = true
	}
	rows, err := s.db.QueryContext(ctx, `SELECT campaign_id FROM campaign_members WHERE actor_id=?`, actorID)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	found := false
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return false, err
		}
		found = found || want[id]
	}
	return found, rows.Err()
}

// campaignAliasTarget follows the stored alias map to the current ID. The
// walk is bounded by len(aliases)+1, the exact upper bound of any acyclic
// chain, so it never truncates a legitimate chain (a fixed cap returned a
// non-root for chains longer than it) and still terminates on a corrupt map.
func campaignAliasTarget(aliases map[string]string, id string) string {
	for i := 0; i <= len(aliases); i++ {
		n, ok := aliases[id]
		if !ok || n == id {
			return id
		}
		id = n
	}
	return id
}

// ResolveCampaignID follows aliases and reports whether the campaign exists.
func (s *Store) ResolveCampaignID(ctx context.Context, id string) (string, bool, error) {
	aliases, err := s.CampaignAliases(ctx)
	if err != nil {
		return "", false, err
	}
	return s.resolveCampaignID(ctx, aliases, id)
}

func (s *Store) resolveCampaignID(ctx context.Context, aliases map[string]string, id string) (string, bool, error) {
	id = campaignAliasTarget(aliases, id)
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM campaigns WHERE id=?`, id).Scan(&n); err != nil {
		return "", false, err
	}
	return id, n == 1, nil
}

// SaveGrouping replaces the derived campaign set and records identity, unless
// an operator edit landed after the grouping read the edits (lastEditID).
//
// The edit check runs inside the same writeMu transaction as the replace, and
// AppendCampaignEdit takes writeMu too, so an edit either commits before the
// check (and the save is refused) or after the save (and the next grouping
// sees it). lastEditID must be the largest edit ID the grouping read; edit IDs
// are AUTOINCREMENT and never reused, so MAX(id) only grows.
//
// campaign_ids is replaced, not upserted: Group was validated against a
// contract where the next run is fed exactly the previous Output.Assignments.
// An upsert would resurrect rows Group deliberately dropped (attribution ties
// left unassigned, floating values in unemitted components, values purged by
// retention) as stale ownership claims, which fuse campaigns that Group kept
// apart.
//
// A grouping carrying any empty or duplicate identifier is rejected whole
// with ErrInvalidGrouping before the transaction; the previous grouping stays
// in place.
func (s *Store) SaveGrouping(ctx context.Context, rows []CampaignRow, assign []CampaignAssignmentRow, aliases map[string]string, lastEditID int64) error {
	if err := validateGrouping(rows, assign, aliases); err != nil {
		return err
	}
	now := formatFixedUTC(time.Now())
	return s.WithTxContext(ctx, func(tx *sql.Tx) error {
		var maxEdit int64
		if err := tx.QueryRow(`SELECT COALESCE(MAX(id),0) FROM campaign_edits`).Scan(&maxEdit); err != nil {
			return err
		}
		if maxEdit != lastEditID {
			return ErrStaleGrouping
		}
		for _, q := range []string{`DELETE FROM campaign_members`, `DELETE FROM campaigns`, `DELETE FROM campaign_ids`} {
			if _, err := tx.Exec(q); err != nil {
				return err
			}
		}
		// Multi-row statements (execBatched): the replace rewrites every
		// campaign, member, assignment and alias under writeMu, and with
		// modernc.org/sqlite each single-row Exec recompiles its statement.
		if err := execBatched(ctx, tx, `INSERT INTO campaigns(id,anchor_kind,anchor_value,suggested_name,name,notes,first_seen,last_seen,actors,ips,sessions,kinds,search,updated_at) VALUES`,
			`(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, ``, len(rows), func(i int) []any {
				c := rows[i]
				return []any{c.ID, c.AnchorKind, c.AnchorValue, c.SuggestedName, c.Name, c.Notes,
					fmtCampaignTime(c.FirstSeen), fmtCampaignTime(c.LastSeen), c.Actors, c.IPs, c.Sessions, c.Kinds, c.Search, now}
			}); err != nil {
			return err
		}
		type member struct {
			campaign string
			m        CampaignMemberRow
		}
		var members []member
		for _, c := range rows {
			for _, m := range c.Members {
				members = append(members, member{c.ID, m})
			}
		}
		if err := execBatched(ctx, tx, `INSERT INTO campaign_members(campaign_id,actor_id,sessions,ips,reasons) VALUES`, `(?,?,?,?,?)`, ``, len(members), func(i int) []any {
			m := members[i]
			return []any{m.campaign, m.m.ActorID, m.m.Sessions, m.m.IPs, m.m.Reasons}
		}); err != nil {
			return err
		}
		if err := execBatched(ctx, tx, `INSERT INTO campaign_ids(kind,value,campaign_id,seq) VALUES`, `(?,?,?,?)`, ``, len(assign), func(i int) []any {
			a := assign[i]
			return []any{a.Kind, a.Value, a.CampaignID, a.Seq}
		}); err != nil {
			return err
		}
		// aliases is Group's complete map: a revived ID drops its alias.
		if _, err := tx.Exec(`DELETE FROM campaign_aliases`); err != nil {
			return err
		}
		olds := make([]string, 0, len(aliases))
		for o := range aliases {
			olds = append(olds, o)
		}
		sort.Strings(olds) // deterministic statements
		return execBatched(ctx, tx, `INSERT INTO campaign_aliases(old_id,new_id,created_at) VALUES`, `(?,?,?)`, ``, len(olds), func(i int) []any {
			return []any{olds[i], aliases[olds[i]], now}
		})
	})
}

func (s *Store) ArtifactPathForSHA256(ctx context.Context, sha string) (string, bool, error) {
	if err := s.ensureArtifactsTable(); err != nil {
		return "", false, err
	}
	var p string
	err := s.db.QueryRowContext(ctx, `SELECT local_path FROM artifacts WHERE sha256=? AND COALESCE(local_path,'')<>'' AND status='fetched' ORDER BY id DESC LIMIT 1`, strings.ToLower(sha)).Scan(&p)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	return p, err == nil, err
}

const campaignSummaryColumns = `c.id, c.name, c.suggested_name, c.actors, c.ips, c.sessions, c.first_seen, c.last_seen, c.kinds, c.search`

func scanCampaignSummary(sc interface{ Scan(...any) error }, extra ...any) (CampaignSummary, error) {
	var c CampaignSummary
	var first, last, kinds string
	dest := append([]any{&c.ID, &c.Name, &c.SuggestedName, &c.Actors, &c.IPs, &c.Sessions, &first, &last, &kinds, &c.Search}, extra...)
	err := sc.Scan(dest...)
	c.FirstSeen, c.LastSeen = parseCampaignTime(first), parseCampaignTime(last)
	if kinds != "" {
		c.Kinds = strings.Split(kinds, ",")
	}
	return c, err
}

func (s *Store) ListCampaigns(ctx context.Context, limit int) ([]CampaignSummary, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+campaignSummaryColumns+` FROM campaigns c ORDER BY c.last_seen DESC, c.id LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CampaignSummary
	for rows.Next() {
		c, err := scanCampaignSummary(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) CampaignsForActor(ctx context.Context, actorID string) ([]CampaignSummary, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+campaignSummaryColumns+` FROM campaigns c JOIN campaign_members m ON m.campaign_id=c.id WHERE m.actor_id=? ORDER BY c.id`, actorID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CampaignSummary
	for rows.Next() {
		c, err := scanCampaignSummary(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// GetCampaign resolves aliases, then a case-insensitive name or suggested
// name. sql.ErrNoRows when nothing matches; an *AmbiguousCampaignError
// (errors.Is ErrAmbiguousCampaign) when a name matches more than one campaign.
func (s *Store) GetCampaign(ctx context.Context, idOrName string) (CampaignDetail, error) {
	var d CampaignDetail
	idOrName = strings.TrimSpace(idOrName)
	if idOrName == "" {
		// A blank name would match every campaign whose name is unset.
		return d, sql.ErrNoRows
	}
	aliases, err := s.CampaignAliases(ctx)
	if err != nil {
		return d, err
	}
	id, exists, err := s.resolveCampaignID(ctx, aliases, idOrName)
	if err != nil {
		return d, err
	}
	if !exists {
		// Not an ID: a case-insensitive name or suggested name. Anything
		// matching more than one campaign is ambiguous. Name and suggested
		// name are pooled on purpose: an operator who renamed one "Outlaw/Dota"
		// component to "Outlaw/Dota" still has siblings answering to it.
		ids, err := s.campaignStrings(ctx, idOrName, `SELECT id FROM campaigns
WHERE lower(name)=lower(?1) OR lower(suggested_name)=lower(?1) ORDER BY id`)
		if err != nil {
			return d, err
		}
		switch len(ids) {
		case 0:
			return d, sql.ErrNoRows
		case 1:
			id = ids[0]
		default:
			return d, &AmbiguousCampaignError{Name: idOrName, IDs: ids}
		}
	}
	row := s.db.QueryRowContext(ctx, `SELECT `+campaignSummaryColumns+`, c.notes, c.anchor_kind, c.anchor_value FROM campaigns c
WHERE c.id=?`, id)
	summary, err := scanCampaignSummary(row, &d.Notes, &d.AnchorKind, &d.AnchorValue)
	if err != nil {
		return d, err // sql.ErrNoRows when absent
	}
	d.CampaignSummary = summary
	mrows, err := s.db.QueryContext(ctx, `SELECT m.actor_id, COALESCE(a.primary_ip,''), COALESCE(a.playbook,''), m.sessions, m.ips, m.reasons
FROM campaign_members m LEFT JOIN actors a ON a.id=m.actor_id WHERE m.campaign_id=? ORDER BY m.actor_id LIMIT ?`, d.ID, campaignDetailCap)
	if err != nil {
		return d, err
	}
	for mrows.Next() {
		var m CampaignMemberDetail
		if err := mrows.Scan(&m.ActorID, &m.PrimaryIP, &m.Playbook, &m.Sessions, &m.IPs, &m.Reasons); err != nil {
			mrows.Close()
			return d, err
		}
		d.Members = append(d.Members, m)
	}
	if err := mrows.Err(); err != nil {
		mrows.Close()
		return d, err
	}
	if err := mrows.Close(); err != nil {
		return d, err
	}
	for _, q := range []struct {
		dst *int
		sql string
	}{
		{&d.MembersTotal, `SELECT COUNT(*) FROM campaign_members WHERE campaign_id=?`},
		{&d.HASSHesTotal, `SELECT COUNT(DISTINCT a.hassh) FROM actors a JOIN campaign_members m ON m.actor_id=a.id WHERE m.campaign_id=? AND COALESCE(a.hassh,'')<>''`},
		{&d.ClientsTotal, `SELECT COUNT(DISTINCT a.ssh_client) FROM actors a JOIN campaign_members m ON m.actor_id=a.id WHERE m.campaign_id=? AND COALESCE(a.ssh_client,'')<>''`},
	} {
		if err := s.db.QueryRowContext(ctx, q.sql, d.ID).Scan(q.dst); err != nil {
			return d, err
		}
	}
	if d.HASSHes, err = s.campaignStrings(ctx, d.ID, `SELECT DISTINCT a.hassh FROM actors a JOIN campaign_members m ON m.actor_id=a.id WHERE m.campaign_id=? AND COALESCE(a.hassh,'')<>'' ORDER BY 1 LIMIT ?`, campaignDetailCap); err != nil {
		return d, err
	}
	if d.Clients, err = s.campaignStrings(ctx, d.ID, `SELECT DISTINCT a.ssh_client FROM actors a JOIN campaign_members m ON m.actor_id=a.id WHERE m.campaign_id=? AND COALESCE(a.ssh_client,'')<>'' ORDER BY 1 LIMIT ?`, campaignDetailCap); err != nil {
		return d, err
	}
	if d.Hosts, d.HostsTotal, err = s.campaignHosts(ctx, d.ID); err != nil {
		return d, err
	}
	d.Edits, err = s.campaignEditsFor(ctx, campaignIDsResolvingTo(aliases, d.ID))
	return d, err
}

// campaignIDsResolvingTo is the campaign's own ID plus every alias source
// (including chains) that resolves to it: the small set edits can be filed
// under.
func campaignIDsResolvingTo(aliases map[string]string, id string) []string {
	ids := []string{id}
	for old := range aliases {
		if old != id && campaignAliasTarget(aliases, old) == id {
			ids = append(ids, old)
		}
	}
	sort.Strings(ids[1:])
	return ids
}

// campaignEditsFor reads only the edits filed under ids, so a detail request
// never scans the whole campaign_edits history.
func (s *Store) campaignEditsFor(ctx context.Context, ids []string) ([]CampaignEditRow, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	q := `SELECT id, campaign_id, action, arg, who, created_at FROM campaign_edits WHERE campaign_id IN (?` +
		strings.Repeat(",?", len(ids)-1) + `) ORDER BY id`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CampaignEditRow
	for rows.Next() {
		var r CampaignEditRow
		var at string
		if err := rows.Scan(&r.ID, &r.CampaignID, &r.Action, &r.Arg, &r.Who, &at); err != nil {
			return nil, err
		}
		r.CreatedAt = parseCampaignTime(at)
		out = append(out, r)
	}
	return out, rows.Err()
}

// campaignHosts returns the first campaignDetailCap payload hosts in sort
// order and the true number of distinct hosts. The host is parsed from the
// URL in Go, so SQL cannot count it: the distinct URLs are streamed and only
// the host set is held (the old code read the first 500 URLs, which both
// under-counted and could drop a host that sorted early).
//
// Cost: artifacts has no actor_id index, so this scans artifacts once per
// call (EXPLAIN: SCAN ar, then a campaign_members key probe per row). It runs
// only on demand (a campaign detail request, never a poll or a
// worker tick), and artifacts holds thousands of rows, so no index is added
// for it; revisit if the detail view is ever polled.
func (s *Store) campaignHosts(ctx context.Context, id string) ([]string, int, error) {
	if err := s.ensureArtifactsTable(); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT ar.url FROM artifacts ar JOIN campaign_members m ON m.actor_id=ar.actor_id WHERE m.campaign_id=? AND ar.url LIKE 'http%'`, id)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	seen := map[string]bool{}
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, 0, err
		}
		if u, err := url.Parse(raw); err == nil && u.Hostname() != "" {
			seen[u.Hostname()] = true
		}
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	hosts := make([]string, 0, len(seen))
	for h := range seen {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	return hosts[:min(len(hosts), campaignDetailCap)], len(seen), nil
}

func (s *Store) campaignStrings(ctx context.Context, id, query string, extra ...any) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, query, append([]any{id}, extra...)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) ListScriptFamilies(ctx context.Context, limit int) ([]ScriptFamilyRow, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := s.db.QueryContext(ctx, `SELECT family, display, variants, reason, sessions, actors, ips, command_count, distinctive, links, first_seen, last_seen
FROM script_families ORDER BY sessions DESC, family LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ScriptFamilyRow
	for rows.Next() {
		var f ScriptFamilyRow
		var d, l int
		var first, last string
		if err := rows.Scan(&f.Family, &f.Display, &f.Variants, &f.Reason, &f.Sessions, &f.Actors, &f.IPs, &f.CommandCount, &d, &l, &first, &last); err != nil {
			return nil, err
		}
		f.Distinctive, f.Links, f.FirstSeen, f.LastSeen = d == 1, l == 1, parseCampaignTime(first), parseCampaignTime(last)
		out = append(out, f)
	}
	return out, rows.Err()
}

// GetScript returns sql.ErrNoRows when the fingerprint is unknown.
func (s *Store) GetScript(ctx context.Context, fp string) (ScriptDetail, error) {
	d := ScriptDetail{Fingerprint: fp}
	if err := s.db.QueryRowContext(ctx, `SELECT display, family FROM scripts WHERE fingerprint=?`, fp).Scan(&d.Display, &d.Family); err != nil {
		return d, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT session_id, actor_id, src_ip, first_seen FROM session_scripts WHERE fingerprint=? ORDER BY first_seen DESC LIMIT 500`, fp)
	if err != nil {
		return d, err
	}
	defer rows.Close()
	seen := map[string]bool{}
	for rows.Next() {
		var x ScriptSession
		var first string
		if err := rows.Scan(&x.SessionID, &x.ActorID, &x.SrcIP, &first); err != nil {
			return d, err
		}
		x.FirstSeen = parseCampaignTime(first)
		d.Sessions = append(d.Sessions, x)
		if !seen[x.ActorID] {
			seen[x.ActorID] = true
			d.Actors = append(d.Actors, x.ActorID)
		}
	}
	return d, rows.Err()
}
