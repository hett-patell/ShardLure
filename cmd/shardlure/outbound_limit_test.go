package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// outboundCLIFiles maps each outbound command's CLI file to the Options field
// its --limit must feed. All three commands share the invariant these tests
// pin: the budget is enforced INSIDE the intel package, after Vet and dedup —
// never by shrinking the candidate list in the CLI.
var outboundCLIFiles = map[string]string{
	"report.go":          "MaxReports",
	"share.go":           "MaxUploads",
	"share_urlhaus.go":   "MaxSubmissions",
	"share_threatfox.go": "MaxSubmissions",
}

// TestCLIDoesNotTruncateCandidatesBeforeTheGate is a source-level invariant on
// every outbound command.
//
// Why a source test rather than a behavioural one: this exact defect has now
// shipped three times — `share bazaar`, `report abuseipdb`, and (as a SQL
// LIMIT) `share urlhaus` — and each time it was one expression in the CLI,
// ahead of the gate. `share threatfox` is guarded here from the start for the
// same reason. Candidates arrive best-first, which is also
// dedup-hit-first on any deployment with history, so the budget was spent
// re-examining things already shared or reported and the run shipped nothing.
// The package-level tests pin Share/Report correctly, but none of them can see
// the CLI re-adding a truncation in front — verified by mutation.
//
// The guard TAINT-TRACKS the candidate data instead of matching one spelling.
// The first version matched only the assignment `cands = cands[:...]`, and
// mutation testing showed `limited := cands; limited = limited[:*limit]; cands
// = limited` walked straight past it — the defect is "the candidate slice got
// shorter before the gate", not one syntax for it. So: seed taint at every
// identifier assigned from a candidate collector (a call whose name contains
// "Candidates"), propagate through assignments to fixpoint (including append
// conversions like `cands = append(cands, conv(r))` inside a range over tainted
// rows), and ban slicing anything tainted. Display slices of strings
// (`sha[:12]`, `url[:69]`) and the dispatcher's `args[1:]` stay legal because
// they never touch candidate data.
//
// AST rather than grep so a comment quoting the banned pattern can never trip
// it (parser mode 0 drops comments).
func TestCLIDoesNotTruncateCandidatesBeforeTheGate(t *testing.T) {
	for file := range outboundCLIFiles {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, file, nil, 0) // 0 = drop comments
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}

		// Pass 1: build the tainted-identifier set to fixpoint.
		tainted := map[string]bool{}
		mentionsTainted := func(e ast.Expr) bool {
			found := false
			ast.Inspect(e, func(n ast.Node) bool {
				if id, ok := n.(*ast.Ident); ok && tainted[id.Name] {
					found = true
				}
				return !found
			})
			return found
		}
		seedsOrPropagates := func(rhs ast.Expr) bool {
			// Seed: any call whose selector/function name contains "Candidates"
			// (collectReportCandidates, collectShareCandidates, URLhausCandidates).
			seed := false
			ast.Inspect(rhs, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				name := ""
				switch fn := call.Fun.(type) {
				case *ast.Ident:
					name = fn.Name
				case *ast.SelectorExpr:
					name = fn.Sel.Name
				}
				if strings.Contains(name, "Candidates") {
					seed = true
				}
				return !seed
			})
			return seed || mentionsTainted(rhs)
		}
		for changed := true; changed; {
			changed = false
			ast.Inspect(f, func(n ast.Node) bool {
				as, ok := n.(*ast.AssignStmt)
				if !ok {
					return true
				}
				taintAll := false
				for _, rhs := range as.Rhs {
					if seedsOrPropagates(rhs) {
						taintAll = true
						break
					}
				}
				if !taintAll {
					return true
				}
				for _, lhs := range as.Lhs {
					if id, ok := lhs.(*ast.Ident); ok && id.Name != "_" && !tainted[id.Name] {
						tainted[id.Name] = true
						changed = true
					}
				}
				return true
			})
			// Range statements propagate too: `for _, r := range rows` taints r.
			ast.Inspect(f, func(n ast.Node) bool {
				rs, ok := n.(*ast.RangeStmt)
				if !ok || !mentionsTainted(rs.X) {
					return true
				}
				for _, e := range []ast.Expr{rs.Key, rs.Value} {
					if id, ok := e.(*ast.Ident); ok && id != nil && id.Name != "_" && !tainted[id.Name] {
						tainted[id.Name] = true
						changed = true
					}
				}
				return true
			})
		}

		// Pass 2: any slice expression over tainted data is a truncation.
		ast.Inspect(f, func(n ast.Node) bool {
			se, ok := n.(*ast.SliceExpr)
			if !ok || !mentionsTainted(se.X) {
				return true
			}
			t.Errorf("%s:%d: candidate data is sliced in the CLI. --limit must bound "+
				"SUBMISSIONS (MaxUploads / MaxReports / MaxSubmissions), enforced inside the "+
				"intel package after Vet and dedup — truncating here spends the budget on "+
				"already-shared/already-reported entries at the top of the list and ships nothing. "+
				"(Taint-tracked: renaming the variable does not evade this.)",
				file, fset.Position(se.Pos()).Line)
			return true
		})

		// Pass 3: `limit` must not reach a candidate COLLECTOR either. This is
		// how the defect actually shipped in share_urlhaus.go — not a Go slice
		// but `URLhausCandidates(activeDays, *limit)`, a SQL LIMIT applied
		// before the gate. Same truncation, different syntax layer.
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			name := ""
			switch fn := call.Fun.(type) {
			case *ast.Ident:
				name = fn.Name
			case *ast.SelectorExpr:
				name = fn.Sel.Name
			}
			if !strings.Contains(name, "Candidates") {
				return true
			}
			for _, arg := range call.Args {
				usesLimit := false
				ast.Inspect(arg, func(n ast.Node) bool {
					if id, ok := n.(*ast.Ident); ok && id.Name == "limit" {
						usesLimit = true
					}
					return !usesLimit
				})
				if usesLimit {
					t.Errorf("%s:%d: --limit is passed into %s — a bound applied in the candidate "+
						"query truncates BEFORE the gate (a SQL LIMIT is the same defect as a slice). "+
						"Collect unbounded and let MaxSubmissions/MaxUploads/MaxReports spend the budget "+
						"after Vet and dedup.",
						file, fset.Position(call.Pos()).Line, name)
				}
			}
			return true
		})
	}
}

// TestCLIPassesItsLimitAsASubmissionBudget is the positive half: the previous
// test stops the truncation coming back, this one stops the limit being
// quietly dropped instead. Deleting the truncation WITHOUT wiring the budget
// would also pass that test — and would turn --limit into a no-op, shipping
// the entire backlog to a third party in one run.
//
// Two clauses, both mutation-driven:
//   - the Options literal must set the field from *limit (a hardcoded budget
//     would ignore the operator);
//   - the field must not be REASSIGNED after the literal — `opts.MaxReports =
//     0` inserted after an intact literal passed the first clause alone.
func TestCLIPassesItsLimitAsASubmissionBudget(t *testing.T) {
	for file, field := range outboundCLIFiles {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
		found := false
		ast.Inspect(f, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.KeyValueExpr:
				key, ok := v.Key.(*ast.Ident)
				if !ok || key.Name != field {
					return true
				}
				// Must be fed from the --limit flag, not a constant.
				if star, ok := v.Value.(*ast.StarExpr); ok {
					if id, ok := star.X.(*ast.Ident); ok && id.Name == "limit" {
						found = true
						return true
					}
				}
				t.Errorf("%s:%d: %s is set, but not from *limit — the operator's --limit is ignored",
					file, fset.Position(v.Pos()).Line, field)
			case *ast.AssignStmt:
				// Ban post-literal reassignment of any budget field: it undoes the
				// wiring while the literal (and the clause above) stays green.
				for _, lhs := range v.Lhs {
					sel, ok := lhs.(*ast.SelectorExpr)
					if !ok {
						continue
					}
					switch sel.Sel.Name {
					case "MaxReports", "MaxUploads", "MaxSubmissions":
						t.Errorf("%s:%d: %s is reassigned after the Options literal — the budget "+
							"set there is silently overridden",
							file, fset.Position(v.Pos()).Line, sel.Sel.Name)
					}
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
