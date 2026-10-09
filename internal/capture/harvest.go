package capture

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"path/filepath"
	"strings"
	"time"

	"github.com/networkshard/shardlure/internal/intel/deobf"
	"github.com/networkshard/shardlure/internal/safefile"
	"github.com/networkshard/shardlure/internal/store"
)

// Second-stage harvesting. A fetched dropper script lists the binaries it
// would download (one per architecture, usually); queueing those URLs
// captures payloads no attacker command ever named. The script is only ever
// scanned as text: nothing is executed, sourced or evaluated, and the URLs
// are queued, never fetched here — the ArtifactWorker fetches them later
// through SafeFetcher, under the same SSRF, size and host-gate rules as
// every other capture.
const (
	harvestURLsPerScript = 32
	harvestPerHostDaily  = 32
	harvestSourcesPerRun = 64
	harvestHeadBytes     = 8 << 10
	harvestMaxLineBytes  = 64 << 10
)

// isTextScript reports whether head (the file's first bytes, up to 8 KiB)
// looks like a text script: no known binary/archive magic, no NUL, and at
// least 90% printable bytes (tab, LF, CR, 0x20-0x7e, and any byte >= 0x80
// so UTF-8 comments count).
func isTextScript(head []byte) bool {
	if len(head) > harvestHeadBytes {
		head = head[:harvestHeadBytes]
	}
	if len(head) == 0 {
		return false
	}
	for _, magic := range [][]byte{
		[]byte("\x7fELF"),
		[]byte("MZ"),
		[]byte("PK\x03\x04"),
		[]byte("\x1f\x8b"),
		[]byte("BZh"),
		[]byte("\xfd7zXZ\x00"),
		[]byte("7z\xbc\xaf\x27\x1c"),
	} {
		if bytes.HasPrefix(head, magic) {
			return false
		}
	}
	if len(head) >= 262 && string(head[257:262]) == "ustar" {
		return false
	}
	printable := 0
	for _, b := range head {
		switch {
		case b == 0:
			return false
		case b == '\t' || b == '\n' || b == '\r' || (b >= 0x20 && b <= 0x7e) || b >= 0x80:
			printable++
		}
	}
	return printable*10 >= len(head)*9
}

// HarvestURLs returns up to limit distinct http(s) URLs named in text, in
// first-occurrence order. Each line (lines over 64 KiB are skipped) is
// scanned with ExtractURLs, then so are the deobfuscator's final form and
// every decoded layer, so a base64 `echo …|base64 -d|sh` line yields the URL
// it hides. Capture's own `cowrie-` dedup pseudo-keys and non-http(s) forms
// are dropped.
func HarvestURLs(text string, limit int) []string {
	if limit <= 0 {
		return nil
	}
	seen := map[string]struct{}{}
	var out []string
	add := func(urls []string) bool {
		for _, u := range urls {
			if strings.HasPrefix(u, "cowrie-") {
				continue
			}
			lower := strings.ToLower(u)
			if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
				continue
			}
			if _, ok := seen[u]; ok {
				continue
			}
			seen[u] = struct{}{}
			out = append(out, u)
			if len(out) >= limit {
				return false
			}
		}
		return true
	}
	for len(text) > 0 {
		line := text
		if i := strings.IndexByte(text, '\n'); i >= 0 {
			line, text = text[:i], text[i+1:]
		} else {
			text = ""
		}
		if len(line) > harvestMaxLineBytes || strings.TrimSpace(line) == "" {
			continue
		}
		if !add(ExtractURLs(line)) {
			return out
		}
		r := deobf.Decode(line)
		if len(r.Layers) == 0 {
			continue
		}
		if !add(ExtractURLs(r.Final)) {
			return out
		}
		for _, l := range r.Layers {
			if !add(ExtractURLs(l.Decoded)) {
				return out
			}
		}
	}
	return out
}

// harvestScripts reads up to harvestSourcesPerRun fetched artifacts as text
// and queues the URLs found in the scripts among them. Files are opened only
// through the pinned evidence root (never os.Open on a DB path).
func (r *Runner) harvestScripts(ctx context.Context) (int, error) {
	sources, err := r.st.HarvestCandidates(ctx, harvestSourcesPerRun)
	if err != nil || len(sources) == 0 {
		return 0, err
	}
	rootPath, err := filepath.Abs(r.fetch.EvidenceDir)
	if err != nil {
		return 0, safeCaptureError(err, "capture harvest root failed")
	}
	root, err := safefile.OpenRoot(rootPath)
	if err != nil {
		// Not mounted yet, or unsafe: leave the cursor, retry next run.
		return 0, safeCaptureError(err, "capture harvest root failed")
	}
	defer root.Close()
	queued := 0
	for _, src := range sources {
		if err := ctx.Err(); err != nil {
			return queued, err
		}
		text, ok, err := readHarvestScript(root, rootPath, src.LocalPath)
		if err != nil {
			return queued, err
		}
		if !ok {
			if err := r.st.AdvanceHarvestCursor(ctx, src.ID); err != nil {
				return queued, err
			}
			continue
		}
		n, err := r.st.QueueHarvestedURLs(ctx, src, HarvestURLs(text, harvestURLsPerScript), time.Now(), harvestPerHostDaily)
		if err != nil {
			return queued, err
		}
		if n > 0 {
			// The parent's digest only: a harvested URL is attacker text.
			log.Printf("capture: queued %d second-stage URL(s) from payload sha256=%s", n, src.SHA256)
		}
		queued += n
	}
	return queued, nil
}

// readHarvestScript returns the file's text when it is a script. ok=false
// with a nil error means "skip this source for good": the path is outside the
// evidence root, unsafe (symlink, hardlink, not regular), gone (retention), or
// the content is not a text script. A transient error (permission, I/O) is
// returned so the cursor stays and the source is retried.
func readHarvestScript(root *safefile.Root, rootPath, localPath string) (string, bool, error) {
	if !filepath.IsAbs(localPath) {
		return "", false, nil
	}
	rel, err := filepath.Rel(rootPath, filepath.Clean(localPath))
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", false, nil
	}
	f, err := root.OpenRegular(rel)
	if err != nil {
		if errors.Is(err, safefile.ErrNotExist) || errors.Is(err, safefile.ErrUnsafePath) || errors.Is(err, safefile.ErrNotRegular) {
			return "", false, nil
		}
		return "", false, safeCaptureError(err, "capture harvest read failed")
	}
	defer f.Close()
	br := bufio.NewReaderSize(f, harvestHeadBytes)
	head, err := br.Peek(harvestHeadBytes)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, bufio.ErrBufferFull) {
		return "", false, safeCaptureError(err, "capture harvest read failed")
	}
	if !isTextScript(head) {
		return "", false, nil
	}
	data, err := io.ReadAll(io.LimitReader(br, store.HarvestMaxScriptBytes))
	if err != nil {
		return "", false, safeCaptureError(err, "capture harvest read failed")
	}
	return string(data), true, nil
}
