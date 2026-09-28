package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/networkshard/shardlure/internal/store"
)

// Read-only views of the campaign grouping and script families. Every field
// printed here that an attacker chose (script text, SSH key comments, hosts,
// client versions, actor IDs, and anything an operator typed that could have
// been pasted from them) goes through termSafe first.

func cmdCampaigns(st *store.Store, args []string) {
	fs := flag.NewFlagSet("campaigns", flag.ExitOnError)
	limit := fs.Int("limit", 50, "max campaigns to list")
	if err := fs.Parse(args); err != nil {
		fatal(err)
	}
	if fs.NArg() > 0 {
		fatal(fmt.Errorf("unexpected argument %q (usage: shardlure campaigns [--limit=N])", fs.Arg(0)))
	}
	if err := validateListLimit(*limit); err != nil {
		fatal(err)
	}
	list, err := st.ListCampaigns(context.Background(), *limit)
	if err != nil {
		fatal(err)
	}
	writeCampaigns(os.Stdout, list)
}

func writeCampaigns(out io.Writer, list []store.CampaignSummary) {
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "CAMPAIGN\tNAME\tACTORS\tIPS\tSESSIONS\tLINKED BY\tLAST")
	for _, c := range list {
		fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%d\t%s\t%s\n", termSafe(c.ID), campaignDisplayName(c), c.Actors, c.IPs, c.Sessions,
			termSafe(strings.Join(c.Kinds, ",")), formatDay(c.LastSeen))
	}
	w.Flush()
}

// validateListLimit refuses what the store would otherwise silently replace
// with its default of 200: an operator asking for 5000 rows must not quietly
// get 200 and read it as the whole population.
func validateListLimit(n int) error {
	if n < 1 || n > 1000 {
		return fmt.Errorf("--limit must be 1..1000, got %d", n)
	}
	return nil
}

func campaignDisplayName(c store.CampaignSummary) string {
	switch {
	case c.Name != "":
		return termSafe(c.Name)
	case c.SuggestedName != "":
		return termSafe(c.SuggestedName) + " (suggested)"
	}
	return "-"
}

func formatDay(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format("2006-01-02")
}

func cmdCampaign(st *store.Store, args []string) {
	if err := showCampaign(context.Background(), st, os.Stdout, args); err != nil {
		fatal(err)
	}
}

// showCampaign never picks one of several campaigns answering to a name:
// sibling components routinely share a suggested name, and showing the wrong
// one would mislead the operator silently.
func showCampaign(ctx context.Context, st *store.Store, out io.Writer, args []string) error {
	if len(args) != 2 || args[0] != "show" {
		return errors.New("usage: shardlure campaign show <id|name>")
	}
	d, err := st.GetCampaign(ctx, args[1])
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return fmt.Errorf("no such campaign: %s", termSafe(args[1]))
	case errors.Is(err, store.ErrAmbiguousCampaign):
		msg := fmt.Sprintf("ambiguous name %s; use the campaign ID", termSafe(args[1]))
		if ids := campaignsNamed(ctx, st, args[1]); len(ids) > 0 {
			msg += ": " + termSafe(strings.Join(ids, ", "))
		}
		return errors.New(msg)
	case err != nil:
		return err
	}
	writeCampaign(out, d)
	return nil
}

// campaignsNamed lists the IDs matching name the way GetCampaign matches
// (case-insensitive name or suggested name), among the most recent campaigns
// ListCampaigns will return. Best effort: it only decorates the error.
func campaignsNamed(ctx context.Context, st *store.Store, name string) []string {
	list, err := st.ListCampaigns(ctx, 1000)
	if err != nil {
		return nil
	}
	name = strings.TrimSpace(name)
	var ids []string
	for _, c := range list {
		if strings.EqualFold(c.Name, name) || strings.EqualFold(c.SuggestedName, name) {
			ids = append(ids, c.ID)
		}
	}
	return ids
}

func writeCampaign(out io.Writer, d store.CampaignDetail) {
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "campaign\t%s\n", termSafe(d.ID))
	fmt.Fprintf(w, "name\t%s\n", orDash(termSafe(d.Name)))
	fmt.Fprintf(w, "suggested\t%s\n", orDash(termSafe(d.SuggestedName)))
	fmt.Fprintf(w, "anchor\t%s\n", orDash(termSafe(strings.Trim(d.AnchorKind+":"+d.AnchorValue, ":"))))
	fmt.Fprintf(w, "linked by\t%s\n", orDash(termSafe(strings.Join(d.Kinds, ","))))
	fmt.Fprintf(w, "actors\t%d\nIPs\t%d\nsessions\t%d\n", d.Actors, d.IPs, d.Sessions)
	fmt.Fprintf(w, "first seen\t%s\nlast seen\t%s\n", formatDay(d.FirstSeen), formatDay(d.LastSeen))
	fmt.Fprintf(w, "HASSH\t%s\n", orDash(termSafe(strings.Join(d.HASSHes, ", "))))
	fmt.Fprintf(w, "clients\t%s\n", orDash(termSafe(strings.Join(d.Clients, ", "))))
	fmt.Fprintf(w, "payload hosts\t%s\n", orDash(termSafe(strings.Join(d.Hosts, ", "))))
	fmt.Fprintf(w, "notes\t%s\n\n", orDash(termSafe(d.Notes)))
	fmt.Fprintln(w, "MEMBER\tIP\tPLAYBOOK\tSESSIONS\tWHY")
	for _, m := range d.Members {
		fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\n", termSafe(m.ActorID), orDash(termSafe(m.PrimaryIP)),
			orDash(termSafe(m.Playbook)), m.Sessions, memberReasons(m.Reasons))
	}
	w.Flush()
}

// memberReasons renders the stored reasons JSON as "kind value (label)".
// Decoding first matters for safety as well as readability: JSON escapes C0
// controls, but a label decoded anywhere else would carry them raw, so the
// decoded strings are what termSafe must see.
func memberReasons(raw string) string {
	var rs []struct {
		Kind  string `json:"kind"`
		Value string `json:"value"`
		Label string `json:"label"`
	}
	if err := json.Unmarshal([]byte(raw), &rs); err != nil {
		return orDash(termSafe(raw))
	}
	parts := make([]string, 0, len(rs))
	for _, r := range rs {
		p := r.Kind + " " + r.Value
		if r.Label != "" {
			p += " (" + r.Label + ")"
		}
		parts = append(parts, termSafe(p))
	}
	return orDash(strings.Join(parts, "; "))
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func cmdScripts(st *store.Store, args []string) {
	fs := flag.NewFlagSet("scripts", flag.ExitOnError)
	limit := fs.Int("limit", 50, "max script families to list")
	if err := fs.Parse(args); err != nil {
		fatal(err)
	}
	if fs.NArg() > 0 {
		fatal(fmt.Errorf("unexpected argument %q (usage: shardlure scripts [--limit=N])", fs.Arg(0)))
	}
	if err := validateListLimit(*limit); err != nil {
		fatal(err)
	}
	fams, err := st.ListScriptFamilies(context.Background(), *limit)
	if err != nil {
		fatal(err)
	}
	writeScripts(os.Stdout, fams)
}

// shortID keeps the first 12 runes (never bytes, so a multi-byte character
// is not split into invalid UTF-8).
func shortID(s string) string {
	if r := []rune(s); len(r) > 12 {
		return string(r[:12])
	}
	return s
}

func writeScripts(out io.Writer, fams []store.ScriptFamilyRow) {
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "FAMILY\tSESSIONS\tACTORS\tIPS\tLINKS\tFIRST LINE")
	for _, f := range fams {
		first, _, _ := strings.Cut(f.Display, "\n")
		// Escape before truncating so a cut can never split an escape
		// sequence back into a raw control byte.
		fmt.Fprintf(w, "%s\t%d\t%d\t%d\t%v\t%s\n", shortID(termSafe(f.Family)), f.Sessions, f.Actors, f.IPs, f.Links, termSafe(first))
	}
	w.Flush()
}
