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
		// The IDs are the store's own matches (same lower() rule, uncapped),
		// never a second lookup that could disagree with it.
		msg := fmt.Sprintf("ambiguous name %s; use the campaign ID", termSafe(args[1]))
		var amb *store.AmbiguousCampaignError
		if errors.As(err, &amb) && len(amb.IDs) > 0 {
			msg += ": " + termSafe(strings.Join(amb.IDs, ", "))
		}
		return errors.New(msg)
	case err != nil:
		return err
	}
	writeCampaign(out, d)
	return nil
}

// campaignEditsShown is how many of the newest edits campaign show prints;
// the dashboard holds the full history.
const campaignEditsShown = 5

// writeCampaign prints a campaign detail. GetCampaign caps each list at
// campaignDetailCap but returns the true totals, so every list printed short
// of its total says "showing N of M": a campaign cut at 500 members must not
// read as a 500-member campaign (audit I2).
func writeCampaign(out io.Writer, d store.CampaignDetail) {
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "campaign\t%s\n", termSafe(d.ID))
	fmt.Fprintf(w, "name\t%s\n", orDash(termSafe(d.Name)))
	fmt.Fprintf(w, "suggested\t%s\n", orDash(termSafe(d.SuggestedName)))
	fmt.Fprintf(w, "anchor\t%s\n", orDash(termSafe(strings.Trim(d.AnchorKind+":"+d.AnchorValue, ":"))))
	fmt.Fprintf(w, "linked by\t%s\n", orDash(termSafe(strings.Join(d.Kinds, ","))))
	fmt.Fprintf(w, "actors\t%d\nIPs\t%d\nsessions\t%d\n", d.Actors, d.IPs, d.Sessions)
	fmt.Fprintf(w, "first seen\t%s\nlast seen\t%s\n", formatDay(d.FirstSeen), formatDay(d.LastSeen))
	fmt.Fprintf(w, "HASSH\t%s\n", cappedList(d.HASSHes, d.HASSHesTotal))
	fmt.Fprintf(w, "clients\t%s\n", cappedList(d.Clients, d.ClientsTotal))
	fmt.Fprintf(w, "payload hosts\t%s\n", cappedList(d.Hosts, d.HostsTotal))
	fmt.Fprintf(w, "notes\t%s\n\n", orDash(termSafe(d.Notes)))
	fmt.Fprintln(w, "MEMBER\tIP\tPLAYBOOK\tSESSIONS\tWHY")
	for _, m := range d.Members {
		fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\n", termSafe(m.ActorID), orDash(termSafe(m.PrimaryIP)),
			orDash(termSafe(m.Playbook)), m.Sessions, memberReasons(m.Reasons))
	}
	if d.MembersTotal > len(d.Members) {
		fmt.Fprintf(w, "(showing %d of %d members)\n", len(d.Members), d.MembersTotal)
	}
	if len(d.Edits) > 0 {
		// The store returns edits oldest first; print the newest few.
		shown := d.Edits[max(0, len(d.Edits)-campaignEditsShown):]
		fmt.Fprintln(w, "\nEDIT\tWHEN\tWHO\tARG")
		for _, e := range shown {
			when := "-"
			if !e.CreatedAt.IsZero() {
				when = e.CreatedAt.UTC().Format("2006-01-02 15:04")
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", orDash(termSafe(e.Action)), when, orDash(termSafe(e.Who)), orDash(termSafe(e.Arg)))
		}
		if len(shown) < len(d.Edits) {
			fmt.Fprintf(w, "(showing %d of %d edits; the dashboard has the full history)\n", len(shown), len(d.Edits))
		}
	}
	w.Flush()
}

// cappedList joins an escaped list and discloses when the store returned
// fewer entries than total.
func cappedList(items []string, total int) string {
	s := orDash(termSafe(strings.Join(items, ", ")))
	if total > len(items) {
		s += fmt.Sprintf(" (showing %d of %d)", len(items), total)
	}
	return s
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
	if err := runScripts(context.Background(), st, args, os.Stdout); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		fatal(err)
	}
}

// scriptRebuildMessage says plainly what --rebuild did and did not do: the
// worker reads the stored version once per process, so nothing happens until
// the daemon restarts.
const scriptRebuildMessage = "script rebuild requested: restart shardlure-live to rebuild script fingerprints (campaign names and IDs are kept)"

// runScripts lists script families, or with --rebuild forces a script
// fingerprint rebuild (store.ForceScriptRebuild). --rebuild is an action, not
// a listing, so it refuses to be combined with any list flag.
func runScripts(ctx context.Context, st *store.Store, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("scripts", flag.ContinueOnError)
	limit := fs.Int("limit", 50, "max script families to list")
	rebuild := fs.Bool("rebuild", false, "force a script fingerprint rebuild on the next shardlure-live start (after a downgrade and re-upgrade)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q (usage: shardlure scripts [--limit=N] | shardlure scripts --rebuild)", fs.Arg(0))
	}
	if *rebuild {
		var others []string
		fs.Visit(func(f *flag.Flag) {
			if f.Name != "rebuild" {
				others = append(others, "--"+f.Name)
			}
		})
		if len(others) > 0 {
			return fmt.Errorf("--rebuild is an action and takes no list flags (got %s)", strings.Join(others, ", "))
		}
		if err := st.ForceScriptRebuild(ctx); err != nil {
			return err
		}
		fmt.Fprintln(out, scriptRebuildMessage)
		return nil
	}
	if err := validateListLimit(*limit); err != nil {
		return err
	}
	fams, err := st.ListScriptFamilies(ctx, *limit)
	if err != nil {
		return err
	}
	writeScripts(out, fams)
	return nil
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
