package capture

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/store"
)

func TestCaptureHTTPFailureClassification(t *testing.T) {
	for _, tc := range []struct {
		code   int
		status string
	}{
		{401, "failed_permanently"}, {403, "failed_permanently"}, {404, "failed_permanently"},
		{410, "failed_permanently"}, {408, "failed"}, {425, "failed"}, {429, "failed"},
		{500, "failed"}, {503, "failed"}, {206, "invalid"},
	} {
		t.Run(fmt.Sprint(tc.code), func(t *testing.T) {
			f := NewSafeFetcher(t.TempDir(), 1024, 0, nil)
			f.Client.Transport = queueTransport(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: tc.code, Body: io.NopCloser(strings.NewReader("inert fixture"))}, nil
			})
			got, err := f.Fetch(context.Background(), "http://8.8.8.8/fixture")
			if err == nil || got == nil || got.Status != tc.status || got.LocalPath != "" {
				t.Fatalf("result=%+v err=%v; want %s and no evidence", got, err, tc.status)
			}
		})
	}
}

type failureBody struct{ err error }

func (b failureBody) Read([]byte) (int, error) { return 0, b.err }
func (b failureBody) Close() error             { return nil }

func TestCaptureErrorsNeverExposeURLCredentialsOrNestedTransportText(t *testing.T) {
	for _, stage := range []string{"transport", "body", "parse"} {
		t.Run(stage, func(t *testing.T) {
			raw := "http://sensitive-user:sensitive-password@8.8.8.8/fixture?token=sensitive-query"
			f := NewSafeFetcher(t.TempDir(), 1024, 0, nil)
			nested := &url.Error{Op: "Get", URL: raw, Err: errors.New("sensitive-provider-detail")}
			f.Client.Transport = queueTransport(func(*http.Request) (*http.Response, error) {
				if stage == "transport" {
					return nil, nested
				}
				return &http.Response{StatusCode: 200, Body: failureBody{nested}}, nil
			})
			if stage == "parse" {
				raw = strings.Replace(raw, "/fixture", "/%zz", 1)
			}
			got, err := f.Fetch(context.Background(), raw)
			if err == nil || got == nil {
				t.Fatalf("expected safe failure: %+v %v", got, err)
			}
			if strings.Contains(err.Error()+got.Detail, "sensitive-") {
				t.Fatalf("leaked secret: %+v %v", got, err)
			}
		})
	}
}

func TestCaptureCancelledBeforeDNSOrHTTP(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f := NewSafeFetcher(t.TempDir(), 1024, 0, nil)
	f.Client.Transport = queueTransport(func(*http.Request) (*http.Response, error) {
		t.Fatal("cancelled work reached transport")
		return nil, nil
	})
	got, err := f.Fetch(ctx, "http://8.8.8.8/fixture")
	if !errors.Is(err, context.Canceled) || got == nil || got.Status != "failed" {
		t.Fatalf("result=%+v err=%v", got, err)
	}
}

func TestCaptureRedirectPolicySurvivesHTTPWrapping(t *testing.T) {
	for _, target := range []string{"http://sensitive-user:sensitive-password@127.0.0.1/", "http://169.254.169.254/?token=sensitive-query"} {
		f := NewSafeFetcher(t.TempDir(), 1024, 0, nil)
		calls := 0
		f.Client.Transport = queueTransport(func(*http.Request) (*http.Response, error) {
			calls++
			return &http.Response{StatusCode: 302, Header: http.Header{"Location": {target}}, Body: io.NopCloser(strings.NewReader(""))}, nil
		})
		got, err := f.Fetch(context.Background(), "http://8.8.8.8/fixture")
		if got == nil || got.Status != "blocked" || err == nil || calls != 1 {
			t.Fatalf("result=%+v err=%v calls=%d", got, err, calls)
		}
		if strings.Contains(got.Detail+err.Error(), "sensitive-") {
			t.Fatal("redirect secret leaked")
		}
	}
}

func TestCaptureWorkerSafeFailurePersistenceAndLogs(t *testing.T) {
	for _, stage := range []string{"transport", "permanent", "store", "cancelled"} {
		t.Run(stage, func(t *testing.T) {
			st, err := store.Open(filepath.Join(t.TempDir(), "capture.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			raw := "http://sensitive-user:sensitive-password@8.8.8.8/fixture?token=sensitive-query"
			if err := st.UpsertArtifact(store.Artifact{URL: raw, TS: time.Now(), Origin: "quarantine_fetch", Status: "pending"}); err != nil {
				t.Fatal(err)
			}
			f := NewSafeFetcher(t.TempDir(), 1024, 0, nil)
			calls := 0
			f.Client.Transport = queueTransport(func(*http.Request) (*http.Response, error) {
				calls++
				if stage == "permanent" {
					return &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader(""))}, nil
				}
				return nil, &url.Error{Op: "Get", URL: raw, Err: errors.New("sensitive-nested")}
			})
			if stage == "store" {
				if err := st.WithTx(func(tx *sql.Tx) error {
					_, err := tx.Exec(`CREATE TRIGGER reject_claim BEFORE UPDATE ON artifacts BEGIN SELECT RAISE(ABORT, 'sensitive-store-detail'); END`)
					return err
				}); err != nil {
					t.Fatal(err)
				}
			}
			var logs bytes.Buffer
			old := log.Writer()
			log.SetOutput(&logs)
			defer log.SetOutput(old)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if stage == "cancelled" {
				cancel()
			}
			w := NewArtifactWorker(st, f, 5, time.Minute)
			w.tick(ctx)
			rows, err := st.ListRecentArtifacts(10)
			if err != nil || len(rows) != 1 {
				t.Fatalf("rows=%+v err=%v", rows, err)
			}
			var attempts int
			if err := st.ArtifactAttemptCount(raw, &attempts); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(rows[0].Detail+logs.String(), "sensitive-") {
				t.Fatalf("unsafe diagnostics: %s %s", rows[0].Detail, logs.String())
			}
			if stage == "cancelled" && (rows[0].Status != "pending" || attempts != 0 || calls != 0) {
				t.Fatalf("cancelled work consumed attempt: %+v calls=%d", rows[0], calls)
			}
			if stage == "permanent" {
				if rows[0].Status != "failed_permanently" || attempts != 1 {
					t.Fatalf("permanent failure: %+v", rows[0])
				}
				w.tick(ctx)
				if calls != 1 {
					t.Fatalf("permanent failure retried %d times", calls)
				}
			}
		})
	}
}
