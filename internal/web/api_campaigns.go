package web

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/networkshard/shardlure/internal/campaign"
	"github.com/networkshard/shardlure/internal/store"
)

// Campaign and script API. The four read endpoints only read what the
// campaign worker persisted; the edit endpoint records an operator edit and
// wakes the worker. No request ever regroups.

var (
	campaignIDRe  = regexp.MustCompile(`^c-[0-9a-f]{12}$`)
	fingerprintRe = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Edit argument bounds. A name is a label in a list row and a page title; 200
// runes is several times any real campaign name. Notes are free text but live
// in a single row that every detail request returns, so 4000 runes bounds the
// response without cramping a paragraph of analyst context.
const (
	maxCampaignNameRunes     = 200
	maxCampaignNotesRunes    = 4000
	maxCampaignActorIDLen    = 200
	maxCampaignLookupLen     = 200
	campaignEditWho          = "dashboard"
	campaignAmbiguousMessage = "campaign name is ambiguous: several campaigns answer to it; use the campaign ID"
)

// campaignIgnorableKinds are the evidence kinds that link sessions into a
// campaign (ssh_key and payload in the worker, plus linking scripts), each
// with the one value shape that kind's evidence carries. Ignoring any other
// kind, or a value no evidence of that kind can ever have, would be recorded
// in the append-only ledger and do nothing forever, so it is refused (fix-D
// M2; the same reason an unknown remove_actor is refused):
//   - payload: the lowercase sha256 hex the evidence recorder stores
//     (store.RecordCampaignEvidence lowercases before storing);
//   - script: the lowercase 64-hex script fingerprint (script.Fingerprint);
//   - ssh_key: "SHA256:" + unpadded base64 of 32 bytes, as ssh-keygen -l
//     prints it and script.ExtractKeys records it.
var campaignIgnorableKinds = map[string]*regexp.Regexp{
	"payload": fingerprintRe,
	"script":  fingerprintRe,
	"ssh_key": regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`),
}

func writeCampaignJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}

func campaignLimit(r *http.Request) int {
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= 1000 {
		return n
	}
	return 200
}

func campaignJSONTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// rawJSONList passes stored JSON through, degrading anything that is not a
// JSON array to [] so one bad row never breaks the response.
func rawJSONList(s string) json.RawMessage {
	raw := json.RawMessage(strings.TrimSpace(s))
	if len(raw) == 0 || raw[0] != '[' || !json.Valid(raw) {
		return json.RawMessage("[]")
	}
	return raw
}

type campaignSummaryJSON struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	SuggestedName string   `json:"suggestedName"`
	Actors        int      `json:"actors"`
	IPs           int      `json:"ips"`
	Sessions      int      `json:"sessions"`
	FirstSeen     string   `json:"firstSeen"`
	LastSeen      string   `json:"lastSeen"`
	Kinds         []string `json:"kinds"`
	Search        string   `json:"search"`
}

func campaignSummaryToJSON(c store.CampaignSummary) campaignSummaryJSON {
	return campaignSummaryJSON{ID: c.ID, Name: c.Name, SuggestedName: c.SuggestedName, Actors: c.Actors, IPs: c.IPs, Sessions: c.Sessions,
		FirstSeen: campaignJSONTime(c.FirstSeen), LastSeen: campaignJSONTime(c.LastSeen), Kinds: nonNilStrings(c.Kinds), Search: c.Search}
}

func (s *Server) handleCampaigns(w http.ResponseWriter, r *http.Request) {
	list, err := s.st.ListCampaigns(r.Context(), campaignLimit(r))
	if err != nil {
		httpError(w, "campaigns", err, http.StatusInternalServerError)
		return
	}
	out := make([]campaignSummaryJSON, 0, len(list))
	for _, c := range list {
		out = append(out, campaignSummaryToJSON(c))
	}
	total := s.campaignListTotal(r.Context(), "campaigns_total", s.st.CountCampaigns, len(out))
	writeCampaignJSON(w, map[string]any{"generatedAt": campaignJSONTime(time.Now()), "campaigns": out, "total": total,
		"regroup": s.campaignRegroupStatus(r.Context())})
}

// campaignListTotal is the true row count behind a capped list (final audit
// M1: past the cap the panel read "200 script families" and silently dropped
// the smallest). The count is a separate read, so it is floored at the rows
// actually returned. On a count failure the total is omitted (nil) rather
// than failing the list, and the failure is logged at most once per
// radarErrLogEvery; the panel then shows the plain row count.
func (s *Server) campaignListTotal(ctx context.Context, op string, count func(context.Context) (int, error), shown int) any {
	n, err := count(ctx)
	if err != nil {
		s.listTotalErrLog.log(op, err)
		return nil
	}
	if n < shown {
		n = shown
	}
	return n
}

// campaignRegroupJSON tells the dashboard why an edit has not applied yet.
// After an upgrade that changes the script normaliser the worker holds
// regroups until the re-recorded scripts settle (10-12 min normally, up to
// the 30 min deadline): edits are recorded but applied only then, and
// without this the dialog said "applying..." the whole time.
//
// Progress is recorded/target (0..1) while recording, 1 while settling.
// Until is the settling deadline (RFC3339 UTC) once the worker has started
// that clock.
type campaignRegroupJSON struct {
	Held     bool    `json:"held"`
	Phase    string  `json:"phase,omitempty"`
	Progress float64 `json:"progress"`
	Until    string  `json:"until,omitempty"`
}

// campaignRegroupStatus reads the hold through the read-only
// store.ScriptRebuildHoldStatus (never ScriptRebuildHold, which acts on the
// hold and belongs to the worker). nil (JSON null) when it cannot be read:
// the lists still render.
func (s *Server) campaignRegroupStatus(ctx context.Context) *campaignRegroupJSON {
	st, err := s.st.ScriptRebuildHoldStatus(ctx)
	if err != nil {
		return nil
	}
	out := &campaignRegroupJSON{Held: st.Held, Phase: st.Phase}
	switch {
	case !st.Held:
	case st.Phase == "recording" && st.Target > 0:
		out.Progress = math.Min(1, float64(st.Recorded)/float64(st.Target))
	default:
		out.Progress = 1
	}
	if !st.Until.IsZero() {
		out.Until = campaignJSONTime(st.Until)
	}
	return out
}

type campaignMemberJSON struct {
	ActorID   string          `json:"actorId"`
	PrimaryIP string          `json:"primaryIp"`
	Playbook  string          `json:"playbook"`
	Sessions  int             `json:"sessions"`
	IPs       int             `json:"ips"`
	Reasons   json.RawMessage `json:"reasons"`
}

type campaignEditJSON struct {
	Action    string `json:"action"`
	Arg       string `json:"arg"`
	Who       string `json:"who"`
	CreatedAt string `json:"createdAt"`
}

// campaignDetailJSON: members, hasshes, clients and hosts are bounded lists
// (the store caps each); the *Total fields are the true counts, so a client
// shows "N of M" when a list is shorter than its total.
type campaignDetailJSON struct {
	campaignSummaryJSON
	Notes        string               `json:"notes"`
	Anchor       map[string]string    `json:"anchor"`
	Members      []campaignMemberJSON `json:"members"`
	MembersTotal int                  `json:"membersTotal"`
	HASSHes      []string             `json:"hasshes"`
	HASSHesTotal int                  `json:"hasshesTotal"`
	Clients      []string             `json:"clients"`
	ClientsTotal int                  `json:"clientsTotal"`
	Hosts        []string             `json:"hosts"`
	HostsTotal   int                  `json:"hostsTotal"`
	Edits        []campaignEditJSON   `json:"edits"`
}

// handleCampaign looks a campaign up by ID (following aliases) or by a unique
// name or suggested name. A name several campaigns answer to is a 400 asking
// for the ID: showing whichever sorts first would be a silent wrong answer.
func (s *Server) handleCampaign(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" || len(id) > maxCampaignLookupLen {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	d, err := s.st.GetCampaign(r.Context(), id)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		http.Error(w, "not found", http.StatusNotFound)
		return
	case errors.Is(err, store.ErrAmbiguousCampaign):
		// The IDs are ours (c-<hex>), never attacker text, so they can be
		// echoed; listing them lets the operator pick instead of guessing.
		msg := campaignAmbiguousMessage
		var amb *store.AmbiguousCampaignError
		if errors.As(err, &amb) && len(amb.IDs) > 0 {
			msg += ": " + strings.Join(amb.IDs, ", ")
		}
		http.Error(w, msg, http.StatusBadRequest)
		return
	case err != nil:
		httpError(w, "campaign", err, http.StatusInternalServerError)
		return
	}
	out := campaignDetailJSON{campaignSummaryJSON: campaignSummaryToJSON(d.CampaignSummary), Notes: d.Notes,
		Anchor: map[string]string{"kind": d.AnchorKind, "value": d.AnchorValue}, Members: make([]campaignMemberJSON, 0, len(d.Members)),
		HASSHes: nonNilStrings(d.HASSHes), Clients: nonNilStrings(d.Clients), Hosts: nonNilStrings(d.Hosts), Edits: make([]campaignEditJSON, 0, len(d.Edits)),
		MembersTotal: d.MembersTotal, HASSHesTotal: d.HASSHesTotal, ClientsTotal: d.ClientsTotal, HostsTotal: d.HostsTotal}
	for _, m := range d.Members {
		out.Members = append(out.Members, campaignMemberJSON{ActorID: m.ActorID, PrimaryIP: m.PrimaryIP, Playbook: m.Playbook,
			Sessions: m.Sessions, IPs: m.IPs, Reasons: rawJSONList(m.Reasons)})
	}
	for _, e := range d.Edits {
		out.Edits = append(out.Edits, campaignEditJSON{Action: e.Action, Arg: e.Arg, Who: e.Who, CreatedAt: campaignJSONTime(e.CreatedAt)})
	}
	writeCampaignJSON(w, out)
}

// Variant caps (final audit M2). A family stores one variant per member
// fingerprint with no bound, and a bot whose scripts differ only in text the
// normaliser keeps mints one per session, so both responses carry only the
// largest variants beside the true count (variantsTotal). The list is polled
// every 30 s and shows only the count (the palette matches a fingerprint
// prefix against these), so it keeps fewer; the script dialog is on demand
// and lists each variant as a row.
const (
	listVariantCap   = 50
	scriptVariantCap = 200
)

// capVariants returns the stored variants array cut to its limit largest
// entries by sessions (ties in stored order), plus any keep fingerprint that
// fell below the cut, and the array's full length. Anything that is not a
// JSON array of objects degrades to [] with total 0, as rawJSONList does.
func capVariants(stored string, limit int, keep ...string) (json.RawMessage, int) {
	var all []json.RawMessage
	if err := json.Unmarshal(rawJSONList(stored), &all); err != nil {
		return json.RawMessage("[]"), 0
	}
	if len(all) <= limit {
		return rawJSONList(stored), len(all)
	}
	type ranked struct {
		raw         json.RawMessage
		fingerprint string
		sessions    int
	}
	rs := make([]ranked, 0, len(all))
	for _, raw := range all {
		var v struct {
			Fingerprint string `json:"fingerprint"`
			Sessions    int    `json:"sessions"`
		}
		if json.Unmarshal(raw, &v) != nil {
			return json.RawMessage("[]"), 0
		}
		rs = append(rs, ranked{raw, v.Fingerprint, v.Sessions})
	}
	sort.SliceStable(rs, func(i, j int) bool { return rs[i].sessions > rs[j].sessions })
	out := make([]json.RawMessage, 0, limit+len(keep))
	for _, r := range rs[:limit] {
		out = append(out, r.raw)
	}
	for _, r := range rs[limit:] {
		if slices.Contains(keep, r.fingerprint) {
			out = append(out, r.raw)
		}
	}
	b, err := json.Marshal(out)
	if err != nil {
		return json.RawMessage("[]"), 0
	}
	return b, len(all)
}

type scriptFamilyJSON struct {
	Family        string          `json:"family"`
	Display       string          `json:"display"`
	Variants      json.RawMessage `json:"variants"`
	VariantsTotal int             `json:"variantsTotal"`
	Sessions      int             `json:"sessions"`
	Actors        int             `json:"actors"`
	IPs           int             `json:"ips"`
	CommandCount  int             `json:"commandCount"`
	Distinctive   bool            `json:"distinctive"`
	Links         bool            `json:"links"`
	Reason        string          `json:"reason"`
	FirstSeen     string          `json:"firstSeen"`
	LastSeen      string          `json:"lastSeen"`
}

func (s *Server) handleScripts(w http.ResponseWriter, r *http.Request) {
	fams, err := s.st.ListScriptFamilies(r.Context(), campaignLimit(r))
	if err != nil {
		httpError(w, "scripts", err, http.StatusInternalServerError)
		return
	}
	out := make([]scriptFamilyJSON, 0, len(fams))
	for _, f := range fams {
		variants, variantsTotal := capVariants(f.Variants, listVariantCap)
		out = append(out, scriptFamilyJSON{Family: f.Family, Display: f.Display, Variants: variants, VariantsTotal: variantsTotal, Sessions: f.Sessions,
			Actors: f.Actors, IPs: f.IPs, CommandCount: f.CommandCount, Distinctive: f.Distinctive, Links: f.Links, Reason: f.Reason,
			FirstSeen: campaignJSONTime(f.FirstSeen), LastSeen: campaignJSONTime(f.LastSeen)})
	}
	// The same regroup block as the campaigns list: a script rebuild deletes
	// script_families first and RebuildScriptFamilies fills it only with the
	// first regroup after the hold, so for the 10-30 minutes in between this
	// list is legitimately empty and the panel must say why rather than read
	// as data loss (fix-all review M5).
	total := s.campaignListTotal(r.Context(), "scripts_total", s.st.CountScriptFamilies, len(out))
	writeCampaignJSON(w, map[string]any{"generatedAt": campaignJSONTime(time.Now()), "families": out, "total": total,
		"regroup": s.campaignRegroupStatus(r.Context())})
}

type scriptSessionJSON struct {
	SessionID string `json:"sessionId"`
	ActorID   string `json:"actorId"`
	SrcIP     string `json:"srcIp"`
	FirstSeen string `json:"firstSeen"`
}

func (s *Server) handleScript(w http.ResponseWriter, r *http.Request) {
	fp := r.URL.Query().Get("fp")
	if !fingerprintRe.MatchString(fp) {
		http.Error(w, "bad fingerprint", http.StatusBadRequest)
		return
	}
	d, err := s.st.GetScript(r.Context(), fp)
	if errors.Is(err, sql.ErrNoRows) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if err != nil {
		httpError(w, "script", err, http.StatusInternalServerError)
		return
	}
	sessions := make([]scriptSessionJSON, 0, len(d.Sessions))
	for _, x := range d.Sessions {
		sessions = append(sessions, scriptSessionJSON{SessionID: x.SessionID, ActorID: x.ActorID, SrcIP: x.SrcIP, FirstSeen: campaignJSONTime(x.FirstSeen)})
	}
	out := map[string]any{"fingerprint": d.Fingerprint, "display": d.Display, "family": d.Family,
		"sessions": sessions, "actors": nonNilStrings(d.Actors), "sessionsTotal": len(sessions)}
	// The Scripts row counts the whole family, but GetScript lists only this
	// fingerprint's sessions (capped at 500). Without the family block the
	// dialog read "4 sessions" under a row claiming 6 and the other variants
	// could not be opened at all (audit-web I1): carry the family totals and
	// every variant with its session count, so the dialog says "this variant:
	// N of M family sessions" and each variant opens through its fingerprint.
	// A lookup failure only omits the block (the script itself still shows).
	//
	// The variant list is capped at scriptVariantCap (largest first, plus
	// this fingerprint and the representative so the dialog can mark them)
	// with the true variantsTotal beside it (final audit M2); this variant's
	// session total is read from the full list before the cut.
	if fam, ok := s.scriptFamily(r.Context(), d.Family); ok {
		out["variants"], out["variantsTotal"] = capVariants(fam.Variants, scriptVariantCap, d.Fingerprint, d.Family)
		out["familySessions"], out["familyActors"], out["familyIps"] = fam.Sessions, fam.Actors, fam.IPs
		var vs []struct {
			Fingerprint string `json:"fingerprint"`
			Sessions    int    `json:"sessions"`
		}
		if json.Unmarshal(rawJSONList(fam.Variants), &vs) == nil {
			for _, v := range vs {
				if v.Fingerprint == d.Fingerprint && v.Sessions > len(sessions) {
					out["sessionsTotal"] = v.Sessions
				}
			}
		}
	}
	writeCampaignJSON(w, out)
}

// scriptFamilyLookupLimit bounds the family lookup below: ListScriptFamilies
// orders by sessions, so a family beyond it is one of the smallest, and the
// dialog then shows the script without the family block.
const scriptFamilyLookupLimit = 1000

// scriptFamily returns the materialised script_families row for family.
// There is no single-family store read yet, so it scans the bounded list; it
// runs only when an analyst opens a script, never on a poll.
func (s *Server) scriptFamily(ctx context.Context, family string) (store.ScriptFamilyRow, bool) {
	if family == "" {
		return store.ScriptFamilyRow{}, false
	}
	fams, err := s.st.ListScriptFamilies(ctx, scriptFamilyLookupLimit)
	if err != nil {
		return store.ScriptFamilyRow{}, false
	}
	for _, f := range fams {
		if f.Family == family {
			return f, true
		}
	}
	return store.ScriptFamilyRow{}, false
}

// handleCampaignEdit validates and records one edit, then wakes the worker.
// Regrouping never runs inside the request: latency stays bounded and the
// edit cannot race the worker's own pass (SaveGrouping refuses a grouping
// computed before this edit, and the wake makes the worker recompute).
//
// Auth and origin follow the other mutating endpoints: bare guard (header
// token, or the session cookie with the same-origin check that
// requireDashboardAuth applies to non-GET requests) plus the method check
// here. Fields: id (campaign ID; optional for ignore_evidence, where it only
// files the edit under that campaign's history), action, arg. IDs are
// recorded literally (see below). The dashboard has a single shared token,
// so every dashboard edit is recorded as who="dashboard"; the CLI records
// "cli".
func (s *Server) handleCampaignEdit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// The largest valid edit is 4000 runes of notes; ParseForm would
	// otherwise buffer up to 10 MB of body.
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	id := strings.TrimSpace(r.PostFormValue("id"))
	action := strings.TrimSpace(r.PostFormValue("action"))
	arg := strings.TrimSpace(r.PostFormValue("arg"))
	if err := validateCampaignEdit(id, action, arg); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Every campaign the edit names must exist: a live campaign or any alias
	// source counts. The resolved ID is used ONLY for that check; the edit
	// is recorded exactly as submitted. Stored aliases include Group's
	// automatic bridge aliases, and Group alone interprets edit IDs (through
	// merge aliases only). Recording the resolution would turn "merge T into
	// A" while A is bridged into B into a permanent merge into B, and would
	// refuse "merge A into B" (make the bridge permanent) as a self-merge.
	// The edit ledger is append-only, so that mistake has no undo.
	//
	// The refusal names the ID and its role: "unknown campaign" is usually a
	// dialog left open across a regroup, "unknown merge target" a typo, and
	// the operator cannot tell which from a bare "unknown campaign". Both IDs
	// already matched campaignIDRe, so echoing them is safe.
	type ref struct{ role, id string }
	refs := []ref{}
	if id != "" {
		refs = append(refs, ref{"campaign", id})
	}
	if action == "merge" {
		refs = append(refs, ref{"merge target", arg})
	}
	for _, ref := range refs {
		_, ok, err := s.st.ResolveCampaignID(r.Context(), ref.id)
		if err != nil {
			httpError(w, "campaign_edit", err, http.StatusInternalServerError)
			return
		}
		if !ok {
			http.Error(w, "unknown "+ref.role+" "+ref.id, http.StatusBadRequest)
			return
		}
	}
	if action == "remove_actor" {
		member, err := s.campaignHoldsActor(r.Context(), id, arg)
		if err != nil {
			httpError(w, "campaign_edit", err, http.StatusInternalServerError)
			return
		}
		if !member {
			http.Error(w, "actor "+arg+" is not a member of campaign "+id, http.StatusBadRequest)
			return
		}
	}
	if err := s.st.AppendCampaignEdit(r.Context(), id, action, arg, campaignEditWho); err != nil {
		httpError(w, "campaign_edit", err, http.StatusInternalServerError)
		return
	}
	if s.onCampaignEdit != nil {
		s.onCampaignEdit()
	}
	writeCampaignJSON(w, map[string]any{"ok": true, "applying": true, "regroup": s.campaignRegroupStatus(r.Context())})
}

// campaignHoldsActor decides whether remove_actor names an actor the campaign
// actually holds. Without it any string was accepted: a typo or an actor from
// another campaign went into the append-only ledger as a removal that can
// never mean anything, and one that WOULD bite if that actor later joined.
//
// The campaign is the merge group of id - every lineage that merges (edit
// ledger only, campaign.MergeAliases, exactly as Group reads them) into the
// same root - so an actor counts when it is a stored member of id, of the
// campaign id was merged into, or of a campaign merged into id that the
// worker has not regrouped yet (the dialog says "applying..." for ~5 s after
// a merge). Membership is matched on those IDs literally: the stored aliases
// also hold Group's automatic bridge aliases, and Group applies a removal to
// the lineage the edit names through merge aliases only, so following them
// would accept a removal filed on a lineage that does not hold the actor.
// The resolution only answers yes/no: the edit is still recorded literally.
//
// Stale-dialog edge: if a regroup auto-aliases the dialog's campaign X into Y
// while it is open, X's members now live under Y and a remove on X is refused
// as "not a member". That is the safe answer (the removal would not do what
// the operator saw); reopening the dialog shows Y, where it applies.
func (s *Server) campaignHoldsActor(ctx context.Context, id, actorID string) (bool, error) {
	rows, err := s.st.CampaignEdits(ctx)
	if err != nil {
		return false, err
	}
	edits := make([]campaign.Edit, 0, len(rows))
	for _, e := range rows {
		edits = append(edits, campaign.Edit{ID: e.ID, CampaignID: e.CampaignID, Action: e.Action, Arg: e.Arg})
	}
	merges := campaign.MergeAliases(edits)
	root := campaign.Resolve(merges, id)
	group := []string{id, root}
	for from := range merges {
		if campaign.Resolve(merges, from) == root {
			group = append(group, from)
		}
	}
	return s.st.CampaignHasMember(ctx, group, actorID)
}

// campaignText accepts valid UTF-8 up to max runes with no control characters
// other than, when multiline, CR/LF/tab.
func campaignText(s string, max int, multiline bool) bool {
	if !utf8.ValidString(s) || utf8.RuneCountInString(s) > max {
		return false
	}
	for _, r := range s {
		if multiline && (r == '\n' || r == '\r' || r == '\t') {
			continue
		}
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// validateCampaignEdit checks the shape of an edit before any store lookup.
// Every action except ignore_evidence names a campaign by ID (names can be
// ambiguous). ignore_evidence is global: its campaign ID is optional, must
// exist when given, and only files the edit under that campaign's history;
// it never scopes which campaigns stop linking on the evidence.
func validateCampaignEdit(id, action, arg string) error {
	needID := action != "ignore_evidence"
	if (needID || id != "") && !campaignIDRe.MatchString(id) {
		return errors.New("missing or malformed campaign id")
	}
	switch action {
	case "rename":
		// An empty name (arg is already trimmed) clears the operator's name:
		// Group reads the latest rename as the name, so a later empty one
		// shows the suggested name again and no longer pins a memberless
		// campaign.
		if !campaignText(arg, maxCampaignNameRunes, false) {
			return errors.New("name must be at most 200 characters on one line")
		}
	case "notes":
		if !campaignText(arg, maxCampaignNotesRunes, true) {
			return errors.New("notes must be at most 4000 characters")
		}
	case "merge":
		if !campaignIDRe.MatchString(arg) {
			return errors.New("merge target must be a campaign id")
		}
		if arg == id { // literal: Group decides what the two IDs resolve to
			return errors.New("a campaign cannot be merged into itself")
		}
	case "remove_actor":
		if arg == "" || len(arg) > maxCampaignActorIDLen || !campaignText(arg, maxCampaignActorIDLen, false) {
			return errors.New("missing or malformed actor id")
		}
	case "ignore_evidence":
		kind, value, ok := strings.Cut(arg, ":")
		shape := campaignIgnorableKinds[kind]
		if !ok || shape == nil || !shape.MatchString(value) {
			return errors.New("evidence must be payload:<sha256 hex>, script:<64-hex fingerprint> or ssh_key:SHA256:<base64>")
		}
	default:
		return errors.New("unknown action")
	}
	return nil
}
