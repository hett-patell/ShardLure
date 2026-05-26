package bazaar

import (
	"bytes"
	"context"
	"encoding/json"
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
	if res.IsDuplicate() {
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
	if !res.IsDuplicate() {
		t.Errorf("IsDuplicate should be true")
	}
	if !res.IsAccepted() {
		t.Errorf("IsAccepted should be true for duplicates")
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
func TestSanitiseTags(t *testing.T) {
	in := []string{"elf", "elf", "linux/x86", "x86_64!", "  ", "shardlure", "shardlure"}
	got := sanitiseTags(in)
	want := []string{"elf", "linuxx86", "x8664", "shardlure"}
	if len(got) != len(want) {
		t.Fatalf("len: got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("tag[%d]: got %q want %q", i, got[i], want[i])
		}
	}
}
