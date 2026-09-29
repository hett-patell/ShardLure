package web

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

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
	maxCampaignEvidenceLen   = 200
	maxCampaignLookupLen     = 200
	campaignEditWho          = "dashboard"
	campaignAmbiguousMessage = "campaign name is ambiguous: several campaigns answer to it; use the campaign ID"
)

// campaignIgnorableKinds are the evidence kinds that link sessions into a
// campaign (ssh_key and payload in the worker, plus linking scripts). Ignoring
// any other kind would be recorded and do nothing, so it is refused.
var campaignIgnorableKinds = map[string]bool{"ssh_key": true, "payload": true, "script": true}

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
	writeCampaignJSON(w, map[string]any{"generatedAt": campaignJSONTime(time.Now()), "campaigns": out})
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

type scriptFamilyJSON struct {
	Family       string          `json:"family"`
	Display      string          `json:"display"`
	Variants     json.RawMessage `json:"variants"`
	Sessions     int             `json:"sessions"`
	Actors       int             `json:"actors"`
	IPs          int             `json:"ips"`
	CommandCount int             `json:"commandCount"`
	Distinctive  bool            `json:"distinctive"`
	Links        bool            `json:"links"`
	Reason       string          `json:"reason"`
	FirstSeen    string          `json:"firstSeen"`
	LastSeen     string          `json:"lastSeen"`
}

func (s *Server) handleScripts(w http.ResponseWriter, r *http.Request) {
	fams, err := s.st.ListScriptFamilies(r.Context(), campaignLimit(r))
	if err != nil {
		httpError(w, "scripts", err, http.StatusInternalServerError)
		return
	}
	out := make([]scriptFamilyJSON, 0, len(fams))
	for _, f := range fams {
		out = append(out, scriptFamilyJSON{Family: f.Family, Display: f.Display, Variants: rawJSONList(f.Variants), Sessions: f.Sessions,
			Actors: f.Actors, IPs: f.IPs, CommandCount: f.CommandCount, Distinctive: f.Distinctive, Links: f.Links, Reason: f.Reason,
			FirstSeen: campaignJSONTime(f.FirstSeen), LastSeen: campaignJSONTime(f.LastSeen)})
	}
	writeCampaignJSON(w, map[string]any{"generatedAt": campaignJSONTime(time.Now()), "families": out})
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
	writeCampaignJSON(w, map[string]any{"fingerprint": d.Fingerprint, "display": d.Display, "family": d.Family,
		"sessions": sessions, "actors": nonNilStrings(d.Actors)})
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
	refs := []string{}
	if id != "" {
		refs = append(refs, id)
	}
	if action == "merge" {
		refs = append(refs, arg)
	}
	for _, ref := range refs {
		_, ok, err := s.st.ResolveCampaignID(r.Context(), ref)
		if err != nil {
			httpError(w, "campaign_edit", err, http.StatusInternalServerError)
			return
		}
		if !ok {
			http.Error(w, "unknown campaign", http.StatusBadRequest)
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
	writeCampaignJSON(w, map[string]bool{"ok": true, "applying": true})
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
		if arg == "" || !campaignText(arg, maxCampaignNameRunes, false) {
			return errors.New("name must be 1-200 characters on one line")
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
		if !ok || !campaignIgnorableKinds[kind] || value == "" || len(value) > maxCampaignEvidenceLen || !campaignText(value, maxCampaignEvidenceLen, false) {
			return errors.New("evidence must be ssh_key:, payload: or script: followed by a value")
		}
	default:
		return errors.New("unknown action")
	}
	return nil
}
