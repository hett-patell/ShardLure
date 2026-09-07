# Vendored web fonts

Latin subsets of the typefaces `themes.css` resolves, served same-origin from
`/fonts/` so both dashboards render identically on an air-gapped or
egress-filtered host and the Content-Security-Policy can keep `font-src 'self'`.

| File | Family | Used by | Source |
|---|---|---|---|
| `inter-var-<sha8>.woff2` | Inter (variable, 400–700) | Signal `--sans` | Google Fonts |
| `jetbrains-mono-var-<sha8>.woff2` | JetBrains Mono (variable, 400–700) | Signal `--mono` | Google Fonts |
| `barlow-{400,500,600,700}-<sha8>.woff2` | Barlow | Meridian `--sans` / `--display` | Google Fonts |
| `ibm-plex-mono-{400,500,600}-<sha8>.woff2` | IBM Plex Mono | Meridian `--mono` | Google Fonts |
| `dm-sans-var-<sha8>.woff2` | DM Sans (variable, opsz 9–40, 400–700) | Sprite `--sans` | Google Fonts |
| `pixelify-sans-var-<sha8>.woff2` | Pixelify Sans (variable, 400–700) | Sprite `--display` | Google Fonts |

`<sha8>` is the first 8 hex digits of the file's SHA-256: the server serves these
as `immutable`, so a refreshed face gets a new name (and a new URL) instead of
new bytes under the old one.

`fonts.css` is generated alongside the files by `scripts/fetch-fonts.sh`; re-run
that script to refresh (it rewrites everything in this directory except this
README). Do not hand-edit `fonts.css`.

## Licence

Every family here is distributed under the
[SIL Open Font License 1.1](https://openfontlicense.org/open-font-license-official-text/).
The OFL permits bundling and redistribution of the font software with this
program provided the fonts are not sold on their own and the reserved font
names are not used for modified versions. Copyright holders:

- Inter — © The Inter Project Authors (rsms.me/inter)
- JetBrains Mono — © The JetBrains Mono Project Authors
- Barlow — © The Barlow Project Authors (github.com/jpt/barlow)
- IBM Plex Mono — © IBM Corp.
- DM Sans — © The DM Sans Project Authors (github.com/googlefonts/dm-fonts)
- Pixelify Sans — © The Pixelify Sans Project Authors (github.com/eifetx/Pixelify-Sans)
