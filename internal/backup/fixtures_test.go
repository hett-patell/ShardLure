package backup

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/config"
	"github.com/networkshard/shardlure/internal/store"
	"github.com/networkshard/shardlure/internal/testutil"
	"github.com/networkshard/shardlure/pkg/models"
	"gopkg.in/yaml.v3"
)

func TestMain(m *testing.M) { testutil.Main(m) }

type testFixture struct {
	Root, Config, Evidence, SourceLog string
	Store                             *store.Store
}

const inertEvidence = "inert evidence bytes; never execute\n"
const inertLog = "{\"eventid\":\"inert\"}\n"

func fixtureHash() string { h := sha256.Sum256([]byte(inertEvidence)); return hex.EncodeToString(h[:]) }
func newFixture(t *testing.T) testFixture {
	t.Helper()
	root := t.TempDir()
	cfg := config.Default()
	cfg.DataDir = root
	cfg.Capture.EvidenceDir = filepath.Join(root, "evidence")
	cfg.Cowrie.Home = filepath.Join(root, "cowrie")
	cfg.Cowrie.JSONLog = filepath.Join(cfg.Cowrie.Home, "var", "log", "cowrie", "cowrie.json")
	for _, path := range []string{filepath.Join(cfg.Capture.EvidenceDir, "quarantine"), filepath.Dir(cfg.Cowrie.JSONLog), filepath.Join(cfg.Cowrie.Home, "var", "lib", "cowrie", "downloads"), filepath.Join(cfg.Cowrie.Home, "var", "lib", "cowrie", "tty")} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	configPath := filepath.Join(root, "shardlure.yaml")
	b, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, b, 0600); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(cfg.DBPath())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	now := time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC)
	for _, kind := range []models.EventKind{models.KindConnect, models.KindCommand, models.KindAccepted} {
		if err := st.InsertEvent(&models.Event{TS: now, Source: "cowrie", Kind: kind, ActorID: "cowrie:inert", Command: "inert command"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.UpsertActor(&models.Actor{ID: "cowrie:inert", Source: "cowrie", FirstSeen: now, LastSeen: now, Notes: "operator note"}); err != nil {
		t.Fatal(err)
	}
	blob := filepath.Join(cfg.Capture.EvidenceDir, "quarantine", fixtureHash())
	if err := os.WriteFile(blob, []byte(inertEvidence), 0600); err != nil {
		t.Fatal(err)
	}
	for _, url := range []string{"https://one.example.test/inert", "https://two.example.test/inert"} {
		if err := st.UpsertArtifact(store.Artifact{TS: now, URL: url, Origin: "quarantine_fetch", Status: "fetched", SHA256: fixtureHash(), SizeBytes: int64(len(inertEvidence)), LocalPath: blob}); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.SetAppSetting("fixture.key", "never-send-fixture-value"); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordBazaarUpload(store.BazaarUpload{SHA256: fixtureHash(), UploadedAt: now, ResponseStatus: "ok"}); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordURLhausSubmission("https://one.example.test/inert", "ok", now); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.Cowrie.JSONLog, []byte(inertLog), 0600); err != nil {
		t.Fatal(err)
	}
	return testFixture{root, configPath, cfg.Capture.EvidenceDir, cfg.Cowrie.JSONLog, st}
}
