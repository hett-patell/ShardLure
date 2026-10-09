package capture

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"os"
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
// are dropped, and so is any URL still holding a shell expansion ($ or `).
func HarvestURLs(text string, limit int) []string {
	if limit <= 0 {
		return nil
	}
	seen := map[string]struct{}{}
	var out []string
	add := func(urls []string) bool {
		for _, u := range urls {
			// A URL still holding shell expansion (`wget http://h/$a` in a
			// per-arch loop) is not fetchable as written; it would spend an
			// attempt and a slot of the host's daily cap on a 4xx. It is
			// rejected, never expanded.
			if strings.HasPrefix(u, "cowrie-") || strings.ContainsAny(u, "$`") {
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
//
// Every source is settled in the run that reads it: a script queues its
// URLs, anything else — not a script, gone, unsafe, outside the root, or any
// open/read error — advances the cursor past it. Only cancellation (or a
// failing store) leaves it. A read error used to keep the cursor and abort the
// batch, so one permanently unreadable file (a sample restored as root 0600,
// a bad sector, a sub-mount safefile refuses) stopped all harvesting forever.
// A skipped script loses its second stage; that is the price of never
// stalling the ones behind it.
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
		// Not mounted yet, or unsafe: deployment state, not a property of a
		// source, so the cursor stays and Run's streak log reports it.
		return 0, &captureError{status: "failed", detail: "capture harvest root failed: " + safefile.Category(err)}
	}
	defer root.Close()
	queued, outside := 0, 0
	for _, src := range sources {
		if err := ctx.Err(); err != nil {
			return queued, err
		}
		text, verdict := readHarvestScript(root, rootPath, src.LocalPath)
		switch verdict {
		case harvestScript:
			n, err := r.st.QueueHarvestedURLs(ctx, src, HarvestURLs(text, harvestURLsPerScript), time.Now(), harvestPerHostDaily)
			if err != nil {
				return queued, err
			}
			if n > 0 {
				// The parent's digest only: a harvested URL is attacker text.
				log.Printf("capture: queued %d second-stage URL(s) from payload sha256=%s", n, src.SHA256)
			}
			queued += n
			continue
		case harvestOutsideRoot:
			outside++
		case harvestNotScript:
		default:
			log.Printf("capture: harvest skipped artifact id=%d sha256=%s: %s", src.ID, shaPrefix(src.SHA256), verdict)
		}
		if err := r.st.AdvanceHarvestCursor(ctx, src.ID); err != nil {
			return queued, err
		}
	}
	r.reportHarvestOutside(outside, len(sources))
	return queued, nil
}

func shaPrefix(sha string) string {
	if len(sha) > 16 {
		return sha[:16]
	}
	return sha
}

// reportHarvestOutside logs once per streak that recorded payload paths do
// not map into the evidence root (a moved evidence_dir, a restored database),
// and once when every source maps again. Fixed text only, never a path.
func (r *Runner) reportHarvestOutside(outside, total int) {
	switch {
	case outside > 0 && !r.harvestOutside:
		log.Printf("capture: harvest skipped %d of %d payload(s) whose recorded path is not under the evidence directory; their scripts are not harvested", outside, total)
		r.harvestOutside = true
	case outside == 0 && total > 0 && r.harvestOutside:
		log.Print("capture: harvest payload paths map into the evidence directory again")
		r.harvestOutside = false
	}
}

// Verdicts of readHarvestScript. Everything but harvestScript advances the
// cursor; the remaining values are fixed error categories, safe to log.
const (
	harvestScript      = "script"
	harvestNotScript   = "not_script"
	harvestOutsideRoot = "outside_root"
)

// openHarvestFile is Root.OpenRegular; a variable so a test can inject an
// error that a root-run test cannot produce with file modes.
var openHarvestFile = func(root *safefile.Root, rel string) (*os.File, error) { return root.OpenRegular(rel) }

// readHarvestScript returns the file's text and harvestScript when it is a
// script. Otherwise the verdict says why it is skipped: harvestNotScript,
// harvestOutsideRoot, or a fixed error category (safefile.Category of the
// open error — ErrNotExist after retention, ErrUnsafePath, ErrNotRegular,
// ErrPermission, ErrIO… — or "read_failed").
func readHarvestScript(root *safefile.Root, rootPath, localPath string) (string, string) {
	if localPath == "" {
		return "", harvestOutsideRoot
	}
	// LocalPath is filepath.Join(EvidenceDir, …): relative when evidence_dir
	// is, so it resolves against the same working directory as rootPath.
	abs, err := filepath.Abs(localPath)
	if err != nil {
		return "", harvestOutsideRoot
	}
	rel, err := filepath.Rel(rootPath, abs)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", harvestOutsideRoot
	}
	f, err := openHarvestFile(root, rel)
	if err != nil {
		if cat := safefile.Category(err); cat != "unknown" {
			return "", cat
		}
		return "", "open_failed"
	}
	defer f.Close()
	br := bufio.NewReaderSize(f, harvestHeadBytes)
	head, err := br.Peek(harvestHeadBytes)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, bufio.ErrBufferFull) {
		return "", "read_failed"
	}
	if !isTextScript(head) {
		return "", harvestNotScript
	}
	data, err := io.ReadAll(io.LimitReader(br, store.HarvestMaxScriptBytes))
	if err != nil {
		return "", "read_failed"
	}
	return string(data), harvestScript
}
