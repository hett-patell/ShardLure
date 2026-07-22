# ShardLure v2 Release Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make a `v2.0.0` tag produce a complete release safely, close the replay and MalwareBazaar policy defects, and deploy against one tested Cowrie revision with atomic patch preflight.

**Architecture:** Keep release orchestration in GitHub Actions, with an annotated tag as the only human trigger and a draft release as the transaction boundary. Keep malware policy centralized in `bazaar.Vet`. Pin Cowrie to the tested `v3.0.8` commit and route every patch caller through one preflight-then-apply orchestrator.

**Tech Stack:** GitHub Actions, GitHub CLI, Python `unittest`, Bash, Go tests, Cowrie Python sources.

---

### Task 1: Transactional GitHub Release Creation

**Files:**
- Create: `scripts/test_release_contracts.py`
- Modify: `.github/workflows/ci.yml`
- Create: `docs/RELEASING.md`
- Modify: `docs/superpowers/plans/2026-07-22-signal-theme-v2.md`

- [ ] **Step 1: Write the failing contract tests**

Create a `unittest.TestCase` which reads repository files relative to `Path(__file__).resolve().parents[1]`. Assert the workflow contains these tokens in increasing string-offset order:

```python
tokens = (
    'gh release view "$TAG"',
    'gh release create "$TAG" --verify-tag --draft --generate-notes',
    'gh release upload "$TAG" release/* --clobber',
    'gh release edit "$TAG" --draft=false --latest',
)
offsets = [workflow.index(token) for token in tokens]
self.assertEqual(offsets, sorted(offsets))
```

Also assert `docs/RELEASING.md` contains `git tag -a v2.0.0`, `git push origin refs/tags/v2.0.0`, and does not instruct the operator to run `gh release create`.

- [ ] **Step 2: Verify RED**

Run: `python3 -m unittest scripts/test_release_contracts.py -v`

Expected: FAIL because the workflow uploads without creating a release and `docs/RELEASING.md` does not exist.

- [ ] **Step 3: Make the workflow create, populate, then publish**

Replace the single upload step with:

```yaml
      - name: Create or reuse draft release
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          TAG="${GITHUB_REF_NAME}"
          if ! gh release view "$TAG" --repo "$GITHUB_REPOSITORY" >/dev/null 2>&1; then
            gh release create "$TAG" --verify-tag --draft --generate-notes --repo "$GITHUB_REPOSITORY"
          fi

      - name: Upload release assets
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          TAG="${GITHUB_REF_NAME}"
          gh release upload "$TAG" release/* --clobber --repo "$GITHUB_REPOSITORY"

      - name: Publish release
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          TAG="${GITHUB_REF_NAME}"
          gh release edit "$TAG" --draft=false --latest --repo "$GITHUB_REPOSITORY"
```

Document: merge and push `main`; create `git tag -a v2.0.0 -m 'ShardLure v2.0.0'`; push only `git push origin refs/tags/v2.0.0`; CI owns release creation, checksums, uploads, and publication. Replace the old manual-release instruction in the Signal plan with a link to `docs/RELEASING.md`.

- [ ] **Step 4: Verify GREEN and commit**

Run: `python3 -m unittest scripts/test_release_contracts.py -v`

Expected: PASS.

Commit: `fix(release): create release before uploading tag assets`

---

### Task 2: Safe Source-Deploy Documentation

**Files:**
- Modify: `scripts/test_release_contracts.py`
- Modify: `README.md`

- [ ] **Step 1: Add a failing README contract**

Add a test asserting `sudo cp /tmp/shardlure` is absent and the README says to run the exact `sudo install` command printed by `scripts/fix-go-sources.sh`.

- [ ] **Step 2: Verify RED**

Run: `python3 -m unittest scripts.test_release_contracts.ReleaseContractTests.test_readme_never_uses_fixed_tmp_binary -v`

Expected: FAIL on the fixed `/tmp/shardlure` path.

- [ ] **Step 3: Correct the source-deploy sequence**

Replace the fixed copy command with: “Run the exact `sudo install ...` command printed by `scripts/fix-go-sources.sh`, then run `sudo python3 scripts/shardlure.py finish`.” Do not expose the helper's process-local build variable as though it exists in the caller.

- [ ] **Step 4: Verify GREEN and commit**

Run: `python3 -m unittest scripts/test_release_contracts.py -v`

Expected: PASS.

Commit: `docs(deploy): follow randomized build output path`

---

### Task 3: Safe Multiline Replay Dry-Run

**Files:**
- Modify: `internal/intel/replay/replay_test.go`
- Modify: `internal/intel/replay/replay.go`

- [ ] **Step 1: Write a failing multiline test**

```go
func TestRenderDryRunCommentsEveryPhysicalLine(t *testing.T) {
	events := []*models.Event{{
		TS: time.Now(), Kind: models.KindCommand,
		Command: "printf safe\nid\nuname -a",
	}}
	s := Render("s", events, Options{DryRun: true})
	want := "# printf safe\n# id\n# uname -a\n"
	if !strings.Contains(s, want) {
		t.Fatalf("multiline command not fully commented:\n%s", s)
	}
	for _, raw := range []string{"\nid\n", "\nuname -a\n"} {
		if strings.Contains(s, raw) {
			t.Fatalf("live attacker line %q", raw)
		}
	}
}
```

- [ ] **Step 2: Verify RED**

Run: `go test ./internal/intel/replay -run TestRenderDryRunCommentsEveryPhysicalLine -count=1 -v`

Expected: FAIL because only the first physical line is prefixed.

- [ ] **Step 3: Prefix every physical line**

In the dry-run branch write `"# " + strings.ReplaceAll(cmd, "\n", "\n# ")`; keep non-dry replay unchanged.

- [ ] **Step 4: Verify GREEN and commit**

Run: `go test ./internal/intel/replay -count=1`

Expected: PASS.

Commit: `fix(replay): comment every dry-run command line`

---

### Task 4: Hard Ten-Day MalwareBazaar Ceiling

**Files:**
- Modify: `internal/intel/bazaar/vet_test.go`
- Modify: `internal/intel/bazaar/share_test.go`
- Modify: `internal/intel/bazaar/vet.go`
- Modify: `internal/config/config_test.go`
- Modify: `internal/config/config.go`
- Modify: `internal/web/bazaar_settings_test.go`
- Modify: `internal/web/api_settings.go`
- Modify: `README.md`
- Modify: `cmd/shardlure/share.go`

- [ ] **Step 1: Write policy regression tests**

Change the override test to prove: four-day sample with `FreshnessDays:3` rejects; nine-day sample with `FreshnessDays:15` remains eligible; twelve-day sample with `FreshnessDays:15` rejects with `10-day`. Add a share test whose HTTP server fails if called and prove a twelve-day sample plus `FreshnessDays:30` yields zero uploads. Add config cases rejecting `-1` and `11`, while allowing zero and 1–10. Add a settings-registry/API test accepting `10`, rejecting `11`, and preserving a previously saved `7` after the rejected save.

- [ ] **Step 2: Verify RED**

Run:

```bash
go test ./internal/intel/bazaar -run 'Freshness|HardCaps' -count=1 -v
go test ./internal/config -run 'Validate' -count=1 -v
go test ./internal/web -run 'BazaarFreshness' -count=1 -v
```

Expected: at least the >10-day policy and settings assertions FAIL.

- [ ] **Step 3: Clamp every policy entry point**

Keep `defaultFreshnessDays = 10`; apply an override only when `0 < value < defaultFreshnessDays`. Validate YAML as `0` or `1..10`. Change the settings registry maximum from `30` to `10`. Keep `--since` as a local candidate selector but document that neither `--since` nor `--sha` bypasses `Vet`.

- [ ] **Step 4: Verify GREEN and commit**

Run: `go test ./internal/intel/bazaar ./internal/config ./internal/web -count=1`

Expected: PASS.

Commit: `fix(bazaar): hard-cap upload freshness at ten days`

---

### Task 5: Require Evidence Beyond Executable Format

**Files:**
- Modify: `internal/intel/bazaar/vet_test.go`
- Modify: `internal/intel/bazaar/share_test.go`
- Modify: `internal/intel/bazaar/vet.go`
- Modify: `README.md`

- [ ] **Step 1: Write format-versus-proof tests**

Add Vet cases proving manual fresh ELF tagged `elf` and manual fresh PE tagged `exe` reject as unconfirmed, while an attacker-fetched novel ELF and a known-family sample accept. Add a share test with a fresh manual `MZ` sample whose HTTP server fails if contacted; expect one skip and no network call.

- [ ] **Step 2: Verify RED**

Run: `go test ./internal/intel/bazaar -run 'Vet|UnprovenExecutable' -count=1 -v`

Expected: FAIL because `elf` and `exe` currently confirm malware independently.

- [ ] **Step 3: Remove only structural confirmation**

Remove `elf` and `exe` from the confirmed-malware tag set. Preserve classification metadata, known family/behavior tags, and the fetched/uploaded provenance path. Update docs to say executable structure is classification, not proof.

- [ ] **Step 4: Verify GREEN and commit**

Run: `go test ./internal/intel/bazaar -count=1`

Expected: PASS.

Commit: `fix(bazaar): require evidence beyond executable format`

---

### Task 6: Pin Cowrie and Preflight Patches Atomically

**Files:**
- Create: `install/cowrie.commit`
- Create: `install/persona/apply-patches.py`
- Create: `scripts/check-cowrie-patches.sh`
- Create: `scripts/test_shardlure.py`
- Modify: `scripts/shardlure.py`
- Modify: `scripts/apply-stealth.sh`
- Modify: `install/persona/patches/bashparse-subshell-pipe.py`
- Modify: `install/persona/patches/grep-case-insensitive.py`
- Modify: `install/persona/patches/honeypot-capture-redirect.py`
- Modify: `.github/workflows/ci.yml`

The tested upstream revision is Cowrie `v3.0.8`, commit `65ded95b2d2b6555be8e4eb95315036a4db361f9`. All three current patches applied successfully to that exact tree before this plan was written.

- [ ] **Step 1: Write failing pin and preflight tests**

In `scripts/test_shardlure.py`, test a `read_cowrie_pin(path)` helper that accepts exactly one lowercase 40-hex line and rejects missing files, `main`, tags, short hashes, uppercase/nonhex, and extra lines. Create `scripts/check-cowrie-patches.sh` to fetch the literal commit into `mktemp -d`, run orchestrator preflight, apply, preflight again, and `git diff --check`; initially it must fail because the orchestrator and `--check` support do not exist.

- [ ] **Step 2: Verify RED**

Run:

```bash
python3 -m unittest scripts/test_shardlure.py -v
bash scripts/check-cowrie-patches.sh
```

Expected: FAIL on missing pin/parser/orchestrator.

- [ ] **Step 3: Add the immutable pin and installer enforcement**

Write only the 40-character commit plus newline to `install/cowrie.commit`. Implement:

```python
def read_cowrie_pin(path: Path) -> str:
    lines = path.read_text(encoding="utf-8").splitlines()
    if len(lines) != 1 or re.fullmatch(r"[0-9a-f]{40}", lines[0]) is None:
        raise ValueError(f"invalid Cowrie pin: {path}")
    return lines[0]
```

New installs fetch and checkout only that detached commit. Existing installs compare `git rev-parse HEAD` to the pin and fail with remediation text on mismatch; never run `git pull`.

- [ ] **Step 4: Add patch `--check` mode and the atomic orchestrator**

Each patch accepts `--check` after the Cowrie path. In check mode, exit 0 without writing when either every exact OLD block is present or the existing patched marker is present; otherwise exit nonzero. `apply-patches.py` enumerates the three scripts in deterministic order, runs all with `--check`, exits before writes if any fail, then runs all normally. `--check` on the orchestrator performs only the first phase. Both `scripts/shardlure.py` and `scripts/apply-stealth.sh` invoke this orchestrator and propagate failure.

- [ ] **Step 5: Prove atomicity and wire CI**

The integration checker must also drift one target in a fresh copy, checksum the other two targets, assert preflight fails, and assert those checksums remain unchanged. Add the unit and integration commands to CI before Go build/test.

- [ ] **Step 6: Verify GREEN and commit**

Run:

```bash
python3 -m unittest scripts/test_shardlure.py -v
bash scripts/check-cowrie-patches.sh
python3 -m py_compile scripts/shardlure.py install/persona/apply-patches.py install/persona/patches/*.py
bash -n scripts/apply-stealth.sh scripts/check-cowrie-patches.sh
```

Expected: PASS; the pinned integration run applies and reapplies cleanly; drift preflight changes no source file.

Commit: `fix(cowrie): pin tested source and preflight patches atomically`

---

### Final Release-Hardening Verification

- [ ] Run:

```bash
python3 -m unittest scripts/test_release_contracts.py scripts/test_shardlure.py -v
go test ./internal/intel/replay ./internal/intel/bazaar ./internal/config ./internal/web -count=1
bash scripts/check-cowrie-patches.sh
bash scripts/check-utf8.sh
go vet ./...
go test ./... -count=1
git diff --check
```

Expected: zero failures. `scripts/vps-finish.sh` remains explicitly legacy for v2.0.0 and is a v2.0.1 deletion/unification follow-up.
