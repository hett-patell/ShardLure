package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// TestCLIDoesNotTruncateCandidatesBeforeTheGate is a source-level invariant on
// both outbound commands.
//
// Why a source test rather than a behavioural one: this exact defect has now
// shipped twice — once in `share bazaar`, once in `report abuseipdb` — and both
// times it was a single line in the CLI, ahead of the gate:
//
//	cands = cands[:limit]
//
// Candidates arrive best-first (newest payloads / worst offenders), which is
// also dedup-hit-first on any deployment with history, so the budget was spent
// re-examining things already shared or already reported and the run shipped
// nothing while real candidates sat below the cut. The package-level tests
// (bazaar.TestShareLimitBoundsUploadsNotCandidates,
// abuseipdb.TestReportLimitBoundsReportsNotCandidates) pin Share and Report
// correctly, but neither can see the CLI re-adding the truncation in front of
// them — verified by mutation: re-inserting the line leaves both suites green.
//
// cmdShareBazaar/cmdReportAbuseIPDB call fatal() (which exits) and take a live
// *store.Store, so driving them end-to-end costs far more than it pins. The
// recurrence mode is textual, so guard it textually — but via the AST, so a
// comment mentioning the bug can never trip it.
func TestCLIDoesNotTruncateCandidatesBeforeTheGate(t *testing.T) {
	for _, file := range []string{"report.go", "share.go"} {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, file, nil, 0) // 0 = drop comments
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			as, ok := n.(*ast.AssignStmt)
			if !ok || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
				return true
			}
			lhs, ok := as.Lhs[0].(*ast.Ident)
			if !ok || lhs.Name != "cands" {
				return true
			}
			if _, ok := as.Rhs[0].(*ast.SliceExpr); !ok {
				return true
			}
			t.Errorf("%s:%d: the CLI re-slices `cands` before handing it to the "+
				"vetting gate. --limit must bound SUBMISSIONS (bazaar.Options.MaxUploads / "+
				"abuseipdb.Options.MaxReports), enforced after Vet and dedup — truncating "+
				"here spends the whole budget on already-shared/already-reported entries at "+
				"the top of the list and ships nothing.",
				file, fset.Position(as.Pos()).Line)
			return true
		})
	}
}

// TestCLIPassesItsLimitAsASubmissionBudget is the positive half: the previous
// test stops the truncation coming back, this one stops the limit being quietly
// dropped instead. Deleting the truncation WITHOUT wiring MaxUploads/MaxReports
// would also pass that test — and would turn --limit into a no-op, uploading
// the entire backlog to a third party in one run.
func TestCLIPassesItsLimitAsASubmissionBudget(t *testing.T) {
	want := map[string]string{
		"share.go":  "MaxUploads",
		"report.go": "MaxReports",
	}
	for file, field := range want {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
		found := false
		ast.Inspect(f, func(n ast.Node) bool {
			kv, ok := n.(*ast.KeyValueExpr)
			if !ok {
				return true
			}
			key, ok := kv.Key.(*ast.Ident)
			if !ok || key.Name != field {
				return true
			}
			// Must be fed from the --limit flag, not a constant: a hardcoded
			// budget would ignore the operator entirely.
			if star, ok := kv.Value.(*ast.StarExpr); ok {
				if id, ok := star.X.(*ast.Ident); ok && id.Name == "limit" {
					found = true
				}
			}
			return true
		})
		if !found {
			t.Errorf("%s does not set %s from *limit — the --limit flag is then either "+
				"unenforced (the whole backlog ships in one run) or enforced by truncation, "+
				"which is the bug this pair of tests exists to prevent", file, field)
		}
	}
}
