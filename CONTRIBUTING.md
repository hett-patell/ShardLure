# Contributing to ShardLure

Thanks for your interest. This project is part of the
[Shard ecosystem](https://github.com/hett-patell?tab=repositories&q=Shard).

## Reporting bugs

Open an issue with:

- What you ran
- What you expected to happen
- What actually happened
- Your OS, language version, and any other relevant runtime info

Include the smallest reproduction you can. A failing test is gold.

## Submitting changes

1. Fork the repo.
2. Create a branch off `main`.
3. Run the test suite (`go test ./...`, `npm test`, etc. — see README).
4. Open a PR with a clear description.

Small, focused PRs land faster than big ones. If a change is large or
exploratory, please open an issue first to discuss scope.

## Coding standards

- Run the project's formatter / linter before pushing.
- Don't introduce new dependencies without justification.
- Don't disable tests to make CI green.

## Security issues

Don't open a public issue or PR for security bugs. See `SECURITY.md`
for the coordinated-disclosure process.
