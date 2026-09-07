package web

import "embed"

//go:embed index.html
var indexHTML string

//go:embed intel.html
var intelHTML string

//go:embed themes.css
var themesCSS []byte

//go:embed cobe-globe.js
var cobeGlobeJS []byte

//go:embed cobe-boot.js
var cobeBootJS []byte

//go:embed vendor/vis-network.min.js
var visNetworkJS []byte

// cobe.esm.js is the vendored globe engine (see the file header for
// provenance). Serving it locally keeps the dashboard functional on
// air-gapped / egress-filtered networks and removes the esm.sh CDN from
// the supply chain of an authenticated page.
//
//go:embed vendor/cobe.esm.js
var cobeESMJS []byte

// Brand assets. logo.svg is the scalable mark (also inlined into the sidebar
// chip); favicon.ico carries 7 sizes (16-256) so browsers and bookmark bars pick
// their own; logo-180.png is the apple-touch / share-card raster.
//
//go:embed logo.svg
var logoSVG []byte

//go:embed favicon.ico
var faviconICO []byte

//go:embed logo-180.png
var logo180PNG []byte

// Self-hosted typography: the latin subsets of the six families themes.css
// resolves, plus the generated fonts.css that declares them. Vendored for the
// same reason as cobe.esm.js — the dashboards must render identically on an
// air-gapped host, and every page load was otherwise a request to two Google
// hosts that the CSP had to whitelist. Refresh with scripts/fetch-fonts.sh.
//
//go:embed fonts/fonts.css fonts/*.woff2
var fontsFS embed.FS
