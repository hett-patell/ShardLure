package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCobeGlobeJSServed(t *testing.T) {
	if len(cobeGlobeJS) < 100 {
		t.Fatal("cobe-globe.js embed empty")
	}
	if !strings.Contains(string(cobeGlobeJS), "COBE_MAX_ARCS") {
		t.Fatal("missing COBE_MAX_ARCS export")
	}
	if !strings.Contains(string(cobeGlobeJS), "cobeEntitiesKey") {
		t.Fatal("missing cobeEntitiesKey export")
	}
	if !strings.Contains(string(cobeGlobeJS), "bindGlobeInteraction") {
		t.Fatal("missing bindGlobeInteraction export")
	}
	if len(cobeBootJS) < 100 {
		t.Fatal("cobe-boot.js embed empty")
	}
	if !strings.Contains(string(cobeBootJS), "window.ShardCobe") {
		t.Fatal("missing ShardCobe in cobe-boot.js")
	}
	s := &Server{}
	mux := http.NewServeMux()
	// Minimal registration matching production route
	mux.HandleFunc("/cobe-globe.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		_, _ = w.Write(cobeGlobeJS)
	})
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/cobe-globe.js", nil)
	mux.ServeHTTP(rec, r)
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "javascript") {
		t.Fatalf("content-type %q", ct)
	}
	_ = s
}

func TestHandleStickerAllowlist(t *testing.T) {
	s := &Server{}
	// sat.svg is the only remaining sticker asset: Sprite's globe stickers are
	// now country-flag emoji (text glyphs, nothing to serve), leaving Meridian's
	// satellite mark as the sole shipped file.
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/stickers/sat.svg", nil)
	s.handleSticker(rec, r)
	if rec.Code != 200 {
		t.Fatalf("sat: %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "svg") {
		t.Fatalf("content-type %q", ct)
	}
	if len(rec.Body.Bytes()) < 50 {
		t.Fatal("empty body")
	}

	rec = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/stickers/../embed.go", nil)
	s.handleSticker(rec, r)
	if rec.Code != 404 {
		t.Fatalf("traversal: want 404 got %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/stickers/nope.svg", nil)
	s.handleSticker(rec, r)
	if rec.Code != 404 {
		t.Fatalf("unknown: want 404 got %d", rec.Code)
	}

	// Removed decorative assets must be gone from the allowlist, not merely
	// deleted from disk — a stale entry would serve an embed error as a 200.
	for _, gone := range []string{"skull.svg", "bolt.svg", "bug.svg", "controller.svg", "shield.svg", "pulse.svg"} {
		rec = httptest.NewRecorder()
		r = httptest.NewRequest(http.MethodGet, "/stickers/"+gone, nil)
		s.handleSticker(rec, r)
		if rec.Code != 404 {
			t.Errorf("%s: want 404 got %d", gone, rec.Code)
		}
	}
}
