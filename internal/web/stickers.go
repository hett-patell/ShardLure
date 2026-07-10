package web

import (
	"net/http"
	"path"
	"strings"
)

// handleSticker serves allowlisted SVG stickers for theme globe overlays.
// Unknown names → 404. No directory traversal.
func (s *Server) handleSticker(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := path.Base(r.URL.Path)
	if name == "." || name == "/" || strings.Contains(name, "..") {
		http.NotFound(w, r)
		return
	}
	if !stickerNames[name] {
		http.NotFound(w, r)
		return
	}
	b, err := readSticker(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "image/svg+xml; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=86400, immutable")
	_, _ = w.Write(b)
}
