# AGENTS.md

**Read [CLAUDE.md](CLAUDE.md).** It is the single source of guidance for this
repository, and it applies verbatim to Codex, Claude Code, and any other agent —
nothing in it is Claude-specific.

This file deliberately contains **no guidance of its own**.

It used to be a byte-identical copy of `CLAUDE.md`, and that is exactly why it
needed fixing: the copy was never updated alongside the code, so it went on
asserting a `v1→v15` migration ladder (the code is at v17), three live-daemon
goroutines (there are four), and an embedded `stickers/*.svg` set that no longer
exists. Two files stating the same facts means one of them is wrong and no build
step can tell you which.

So the fix is structural rather than editorial: one document, duplicated
nowhere. It is the same rule the codebase applies to its own policy — `Vet`
lives in one place per `intel/*` package precisely so the CLI and the dashboard
cannot drift apart (see "the vetting-gate pattern" in `CLAUDE.md`).

If you are tempted to paste a fact here for convenience, don't. Add it to
`CLAUDE.md` instead.
