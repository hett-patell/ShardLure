# Vendored web fonts

Latin subsets of the typefaces `themes.css` resolves, served same-origin from
`/fonts/` so both dashboards render identically on an air-gapped or
egress-filtered host and the Content-Security-Policy can keep `font-src 'self'`.

| File | Family | Used by | Source |
|---|---|---|---|
| `atkinson-hyperlegible-next-var-<sha8>.woff2` | Atkinson Hyperlegible Next (variable, 200–800) | `--sans`, both themes | Google Fonts |
| `atkinson-hyperlegible-mono-var-<sha8>.woff2` | Atkinson Hyperlegible Mono (variable, 200–800) | `--mono`, both themes | Google Fonts |

One family in two widths: the sans sets interface text, the mono sets machine
text (IP addresses, hashes, commands, timestamps). It was drawn to keep
look-alike characters apart (`0`/`O`, `1`/`l`/`I`, `rn`/`m`), which is the
confusion that matters when an analyst compares fingerprints or reads attacker
input.

`<sha8>` is the first 8 hex digits of the file's SHA-256: the server serves these
as `immutable`, so a refreshed face gets a new name (and a new URL) instead of
new bytes under the old one.

`fonts.css` is generated alongside the files by `scripts/fetch-fonts.sh`; re-run
that script to refresh (it rewrites everything in this directory except this
README). Do not hand-edit `fonts.css`.

## Licence

Both families are distributed under the
[SIL Open Font License 1.1](https://openfontlicense.org/open-font-license-official-text/).
The OFL permits bundling and redistribution of the font software with this
program provided the fonts are not sold on their own and the reserved font
names are not used for modified versions.

- Atkinson Hyperlegible Next and Atkinson Hyperlegible Mono — © Braille Institute of America, Inc.
