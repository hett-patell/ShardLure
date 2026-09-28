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

type CampaignDetail struct {
	CampaignSummary
	Notes, AnchorKind, AnchorValue string
	Members                        []CampaignMemberDetail
	HASSHes, Clients, Hosts        []string
	Edits                          []CampaignEditRow
}

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

// ErrInvalidGrouping rejects a grouping carrying an empty identifier. An
// assignment whose campaign ID is "" is fed back into the next run and makes
// it emit a campaign whose ID is "", so nothing empty is ever persisted.
var ErrInvalidGrouping = errors.New("store: campaign grouping has an empty identifier")

func validateGrouping(rows []CampaignRow, assign []CampaignAssignmentRow, aliases map[string]string) error {
	for _, c := range rows {
		if c.ID == "" {
			return fmt.Errorf("%w: campaign row", ErrInvalidGrouping)
		}
		for _, m := range c.Members {
			if m.ActorID == "" {
				return fmt.Errorf("%w: member of %s", ErrInvalidGrouping, c.ID)
			}
		}
	}
	for _, a := range assign {
		if a.Kind == "" || a.Value == "" || a.CampaignID == "" {
			return fmt.Errorf("%w: assignment %s", ErrInvalidGrouping, a.Kind)
		}
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
// actors.last_seen is RFC3339Nano text; the comparison can misorder within
// one second, which is irrelevant at a days-long window.
func (s *Store) CowrieActorPopulation(ctx context.Context, since time.Time) (int, error) {
	var n int
	var err error
	if since.IsZero() {
		err = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM actors WHERE source='cowrie'`).Scan(&n)
	} else {
		err = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM actors WHERE source='cowrie' AND last_seen >= ?`, since.UTC().Format(time.RFC3339Nano)).Scan(&n)
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
	arows, err := s.db.QueryContext(ctx, `SELECT old_id, new_id FROM campaign_aliases WHERE old_id<>'' AND new_id<>''`)
	if err != nil {
		return nil, nil, err
	}
	defer arows.Close()
	aliases := map[string]string{}
	for arows.Next() {
		var o, n string
		if err := arows.Scan(&o, &n); err != nil {
			return nil, nil, err
		}
		aliases[o] = n
	}
	return assign, aliases, arows.Err()
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

func campaignAliasTarget(aliases map[string]string, id string) string {
	for i := 0; i < 64; i++ {
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
	_, aliases, err := s.CampaignIdentity(ctx)
	if err != nil {
		return "", false, err
	}
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
// A grouping carrying any empty identifier is rejected whole with
// ErrInvalidGrouping; the previous grouping stays in place.
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
		for _, q := range []string{`DELETE FROM campaign_members`, `DELETE FROM campaigns`} {
			if _, err := tx.Exec(q); err != nil {
				return err
			}
		}
		for _, c := range rows {
			if _, err := tx.Exec(`INSERT INTO campaigns(id,anchor_kind,anchor_value,suggested_name,name,notes,first_seen,last_seen,actors,ips,sessions,kinds,search,updated_at)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, c.ID, c.AnchorKind, c.AnchorValue, c.SuggestedName, c.Name, c.Notes,
				fmtCampaignTime(c.FirstSeen), fmtCampaignTime(c.LastSeen), c.Actors, c.IPs, c.Sessions, c.Kinds, c.Search, now); err != nil {
				return err
			}
			for _, m := range c.Members {
				if _, err := tx.Exec(`INSERT INTO campaign_members(campaign_id,actor_id,sessions,ips,reasons) VALUES(?,?,?,?,?)`,
					c.ID, m.ActorID, m.Sessions, m.IPs, m.Reasons); err != nil {
					return err
				}
			}
		}
		for _, a := range assign {
			if _, err := tx.Exec(`INSERT INTO campaign_ids(kind,value,campaign_id,seq) VALUES(?,?,?,?)
ON CONFLICT(kind,value) DO UPDATE SET campaign_id=excluded.campaign_id, seq=excluded.seq`, a.Kind, a.Value, a.CampaignID, a.Seq); err != nil {
				return err
			}
		}
		// aliases is Group's complete map: a revived ID drops its alias.
		if _, err := tx.Exec(`DELETE FROM campaign_aliases`); err != nil {
			return err
		}
		for o, n := range aliases {
			if _, err := tx.Exec(`INSERT INTO campaign_aliases(old_id,new_id,created_at) VALUES(?,?,?)`, o, n, now); err != nil {
				return err
			}
		}
		return nil
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
// name. sql.ErrNoRows when nothing matches.
func (s *Store) GetCampaign(ctx context.Context, idOrName string) (CampaignDetail, error) {
	var d CampaignDetail
	idOrName = strings.TrimSpace(idOrName)
	if idOrName == "" {
		// A blank name would match every campaign whose name is unset.
		return d, sql.ErrNoRows
	}
	id, _, err := s.ResolveCampaignID(ctx, idOrName)
	if err != nil {
		return d, err
	}
	row := s.db.QueryRowContext(ctx, `SELECT `+campaignSummaryColumns+`, c.notes, c.anchor_kind, c.anchor_value FROM campaigns c
WHERE c.id=?1 OR lower(c.name)=lower(?2) OR lower(c.suggested_name)=lower(?2)
ORDER BY (c.id=?1) DESC, (lower(c.name)=lower(?2)) DESC, c.id LIMIT 1`, id, idOrName)
	summary, err := scanCampaignSummary(row, &d.Notes, &d.AnchorKind, &d.AnchorValue)
	if err != nil {
		return d, err // sql.ErrNoRows when absent
	}
	d.CampaignSummary = summary
	mrows, err := s.db.QueryContext(ctx, `SELECT m.actor_id, COALESCE(a.primary_ip,''), COALESCE(a.playbook,''), m.sessions, m.ips, m.reasons
FROM campaign_members m LEFT JOIN actors a ON a.id=m.actor_id WHERE m.campaign_id=? ORDER BY m.actor_id`, d.ID)
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
	if d.HASSHes, err = s.campaignStrings(ctx, d.ID, `SELECT DISTINCT a.hassh FROM actors a JOIN campaign_members m ON m.actor_id=a.id WHERE m.campaign_id=? AND COALESCE(a.hassh,'')<>'' ORDER BY 1`); err != nil {
		return d, err
	}
	if d.Clients, err = s.campaignStrings(ctx, d.ID, `SELECT DISTINCT a.ssh_client FROM actors a JOIN campaign_members m ON m.actor_id=a.id WHERE m.campaign_id=? AND COALESCE(a.ssh_client,'')<>'' ORDER BY 1`); err != nil {
		return d, err
	}
	if err := s.ensureArtifactsTable(); err != nil {
		return d, err
	}
	urls, err := s.campaignStrings(ctx, d.ID, `SELECT DISTINCT ar.url FROM artifacts ar JOIN campaign_members m ON m.actor_id=ar.actor_id WHERE m.campaign_id=? AND ar.url LIKE 'http%' LIMIT 500`)
	if err != nil {
		return d, err
	}
	seen := map[string]bool{}
	for _, raw := range urls {
		if u, err := url.Parse(raw); err == nil && u.Hostname() != "" && !seen[u.Hostname()] {
			seen[u.Hostname()] = true
			d.Hosts = append(d.Hosts, u.Hostname())
		}
	}
	sort.Strings(d.Hosts)
	edits, err := s.CampaignEdits(ctx)
	if err != nil {
		return d, err
	}
	_, aliases, err := s.CampaignIdentity(ctx)
	if err != nil {
		return d, err
	}
	for _, e := range edits {
		if campaignAliasTarget(aliases, e.CampaignID) == d.ID {
			d.Edits = append(d.Edits, e)
		}
	}
	return d, nil
}

func (s *Store) campaignStrings(ctx context.Context, id, query string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, query, id)
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
