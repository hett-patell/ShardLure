package web

import (
	"bytes"
	"database/sql"
	"errors"
	"github.com/networkshard/shardlure/internal/settings"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDiagnosticPrivacyHTTPAndLedgerFailure(t *testing.T) {
	var logged bytes.Buffer
	old := log.Writer()
	log.SetOutput(&logged)
	defer log.SetOutput(old)
	sentinel := "inert-private-key /inert/private/path token=inert-secret\nforged"
	w := httptest.NewRecorder()
	httpError(w, "inert_operation", errors.New(sentinel), 500)
	if strings.Contains(logged.String(), "inert-private-key") || strings.Contains(w.Body.String(), "inert-private-key") {
		t.Error("HTTP error boundary leaked private diagnostics")
	}
	logged.Reset()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer upstream.Close()
	s := newIntelTestServer(t, map[string]string{settings.KeyBazaar: "inert", settings.KeyURLhausEndpoint: upstream.URL})
	seedURLhausArtifact(t, s, t.TempDir(), strings.Repeat("a", 64), "http://8.8.8.8/inert.sh", shellPayload, time.Hour)
	if err := s.st.WithTx(func(tx *sql.Tx) error {
		_, err := tx.Exec("CREATE TRIGGER stop_ledger BEFORE INSERT ON urlhaus_submissions BEGIN SELECT RAISE(ABORT,'inert-private-key'); END")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	s.handleURLhausSubmit(w, httptest.NewRequest("POST", "/api/intel/urlhaus/submit", nil))
	if strings.Contains(logged.String(), "inert-private-key") || strings.Contains(w.Body.String(), "inert-private-key") {
		t.Error("provider ledger failure leaked private diagnostics")
	}
	if !strings.Contains(w.Body.String(), `"submitted":0`) {
		t.Fatal("ledger failure counted as submitted")
	}
}
