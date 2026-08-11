package bazaar

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestUploadSuccess verifies the happy path: the client sends a
// multipart POST with both json_data and file parts, the Auth-Key
// header is set, and the inserted response is correctly parsed
// (including the synthesized sample URL).
func TestUploadSuccess(t *testing.T) {
	var (
		gotAuth     string
		gotMethod   string
		gotFile     []byte
		gotJSONBlob map[string]interface{}
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Auth-Key")
		gotMethod = r.Method
		mt, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || mt != "multipart/form-data" {
			t.Errorf("bad content type: %q (%v)", r.Header.Get("Content-Type"), err)
		}
		mr := multipart.NewReader(r.Body, params["boundary"])
		for {
			p, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatalf("next part: %v", err)
			}
			body, _ := io.ReadAll(p)
			switch p.FormName() {
			case "file":
				gotFile = body
			case "json_data":
				_ = json.Unmarshal(body, &gotJSONBlob)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"query_status": "inserted"}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL)
	sha := "abc123abc123abc123abc123abc123abc123abc123abc123abc123abc1230000"
	res, err := c.Upload(context.Background(), "test-key", strings.NewReader("PAYLOAD_BYTES"), sha, Submission{
		Filename:       "sample.elf",
		Tags:           []string{"elf", "x86-64", "linux"},
		Comment:        "test",
		DeliveryMethod: "other",
	})
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	if res.Status != "inserted" {
		t.Errorf("status: want inserted, got %s", res.Status)
	}
	if !res.IsAccepted() {
		t.Errorf("IsAccepted should be true for inserted")
	}
	if res.Status == "file_already_known" {
		t.Errorf("IsDuplicate should be false for inserted")
	}
	if !strings.HasSuffix(res.SampleURL, "/"+sha+"/") {
		t.Errorf("SampleURL: %q does not contain sha", res.SampleURL)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method: want POST, got %s", gotMethod)
	}
	if gotAuth != "test-key" {
		t.Errorf("Auth-Key: want test-key, got %q", gotAuth)
	}
	if string(gotFile) != "PAYLOAD_BYTES" {
		t.Errorf("file part: want PAYLOAD_BYTES, got %q", string(gotFile))
	}
	if got, ok := gotJSONBlob["tags"].([]interface{}); !ok || len(got) != 3 {
		t.Errorf("json_data.tags: want 3 items, got %v", gotJSONBlob["tags"])
	}
	if gotJSONBlob["delivery_method"] != "other" {
		t.Errorf("json_data.delivery_method: got %v", gotJSONBlob["delivery_method"])
	}
}

// TestUploadDuplicate verifies the "file_already_known" response is
// classified as accepted (so the caller records the upload and stops
// retrying it).
func TestUploadDuplicate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"query_status": "file_already_known"}`))
	}))
	defer srv.Close()
	c := NewClient(srv.URL)
	res, err := c.Upload(context.Background(), "k", bytes.NewReader([]byte("x")), "deadbeef", Submission{Filename: "x"})
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	if res.Status != "file_already_known" {
		t.Errorf("IsDuplicate should be true")
	}
	if !res.IsAccepted() {
		t.Errorf("IsAccepted should be true for duplicates")
	}
}

func TestUploadSemanticStatuses(t *testing.T) {
	tests := []struct {
		name     string
		status   string
		accepted bool
		fatal    bool
	}{
		{name: "inserted", status: "inserted", accepted: true},
		{name: "already known", status: "file_already_known", accepted: true},
		{name: "no API key", status: "no_api_key", fatal: true},
		{name: "user blacklisted", status: "user_blacklisted", fatal: true},
		{name: "HTTP POST expected", status: "http_post_expected"},
		{name: "file expected", status: "file_expected"},
		{name: "file too large", status: "file_too_large"},
		{name: "file type not allowed", status: "file_type_not_allowed"},
		{name: "empty status", status: ""},
		{name: "unknown status", status: "future_status"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]string{"query_status": tt.status})
			}))
			defer srv.Close()

			res, err := NewClient(srv.URL).Upload(
				context.Background(), "test-key", strings.NewReader("payload"), "abc123", Submission{Filename: "sample"},
			)
			if res == nil || res.Status != tt.status {
				t.Fatalf("result = %+v, want status %q", res, tt.status)
			}
			if tt.accepted {
				if err != nil {
					t.Fatalf("accepted status returned error: %v", err)
				}
				if !res.IsAccepted() {
					t.Fatal("accepted status classified as rejected")
				}
				return
			}
			if err == nil {
				t.Fatalf("semantic rejection %q returned nil error", tt.status)
			}
			var semanticErr *SemanticError
			if !errors.As(err, &semanticErr) {
				t.Fatalf("error %T is not *SemanticError: %v", err, err)
			}
			if semanticErr.Status != tt.status {
				t.Fatalf("SemanticError.Status = %q, want %q", semanticErr.Status, tt.status)
			}
			if semanticErr.Fatal() != tt.fatal {
				t.Fatalf("SemanticError.Fatal() = %v, want %v", semanticErr.Fatal(), tt.fatal)
			}
			if res.IsAccepted() {
				t.Fatalf("semantic rejection %q classified as accepted", tt.status)
			}
			if tt.status != "" && !strings.Contains(err.Error(), tt.status) {
				t.Fatalf("error %q does not identify status %q", err, tt.status)
			}
		})
	}
}

// TestUploadNoAPIKey ensures the client refuses to make a network
// call when the Auth-Key is empty. Hits before any IO so a tiny
// httptest server is fine — it should never receive the request.
func TestUploadNoAPIKey(t *testing.T) {
	got := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = true
	}))
	defer srv.Close()
	c := NewClient(srv.URL)
	_, err := c.Upload(context.Background(), "", bytes.NewReader([]byte("x")), "abc", Submission{})
	if err == nil {
		t.Fatalf("expected error for missing Auth-Key")
	}
	if got {
		t.Errorf("client made a network call despite missing Auth-Key")
	}
}

// TestUploadHTTPError surfaces transport-level failures rather than
// swallowing them. abuse.ch returns 200 for semantic errors so 5xx
// is unambiguous: their endpoint is down or rate-limiting us.
func TestUploadHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	c := NewClient(srv.URL)
	_, err := c.Upload(context.Background(), "k", bytes.NewReader([]byte("x")), "abc", Submission{})
	if err == nil {
		t.Fatalf("expected error for 5xx")
	}
	if !strings.Contains(err.Error(), "503") {
		t.Errorf("error should mention status: %v", err)
	}
}

// TestSanitiseTags asserts the tag normaliser strips disallowed
// characters and dedupes — both are user-facing contract that an
// inattentive caller (or attacker-supplied filename) can't slip
// junk into the upload.
//
// Output is SORTED: the rule is shared with URLhaus via
// intelutil.SanitiseAbuseChTags, and sorting makes repeated submissions
// byte-identical (diffable in logs). Tag order carries no meaning upstream.
func TestSanitiseTags(t *testing.T) {
	in := []string{"elf", "elf", "linux/x86", "x86_64!", "  ", "shardlure", "shardlure"}
	got := sanitiseTags(in)
	want := []string{"elf", "linuxx86", "shardlure", "x8664"}
	if len(got) != len(want) {
		t.Fatalf("len: got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("tag[%d]: got %q want %q", i, got[i], want[i])
		}
	}
}
