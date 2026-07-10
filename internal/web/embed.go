package web

import (
	"embed"
	"io/fs"
)

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

//go:embed stickers/*.svg
var stickerFS embed.FS

// stickerNames is the allowlist of files served under /stickers/.
var stickerNames = map[string]bool{
	"skull.svg": true, "bolt.svg": true, "bug.svg": true,
	"shield.svg": true, "controller.svg": true,
	"sat.svg": true, "pulse.svg": true,
}

func readSticker(name string) ([]byte, error) {
	return fs.ReadFile(stickerFS, "stickers/"+name)
}
