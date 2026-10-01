package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

// TestIntelActorUsersAreCached pins the ARM-rehearsal fix: /api/intel's
// per-actor top usernames were a ROW_NUMBER() window over every username of
// the 80 listed actors on every 5 s poll (4.05 s of a 4.38 s profile). A
// second request inside actorUsersTTL must not reach the store; an expired
// entry is served at once and refreshed by one background query; a failed
// refresh keeps the last-good lists; after shutdown no refresh starts.
func TestIntelActorUsersAreCached(t *testing.T) {
	s, st := hasshTestServer(t)
	for _, ip := range []string{"198.51.100.1", "198.51.100.2"} {
		now := time.Now().UTC()
		if err := st.UpsertActor(&models.Actor{ID: "journal:" + ip, Source: models.SourceJournal, PrimaryIP: ip, FirstSeen: now, LastSeen: now}); err != nil {
			t.Fatal(err)
		}
	}
	var mu sync.Mutex
	calls, fail := 0, false
	var gotIDs [][]string
	s.actorUsersFetch = func(ctx context.Context, ids []string, n int) (map[string][]models.ActorUser, error) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		gotIDs = append(gotIDs, append([]string(nil), ids...))
		if fail {
			return nil, errors.New("store down")
		}
		out := map[string][]models.ActorUser{}
		for _, id := range ids {
			out[id] = []models.ActorUser{{ActorID: id, Username: "root", Count: calls}}
		}
		return out, nil
	}
	count := func() int { mu.Lock(); defer mu.Unlock(); return calls }
	topUser := func() (int, int) {
		rec := httptest.NewRecorder()
		s.handleIntel(rec, httptest.NewRequest(http.MethodGet, "/api/intel", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("intel = %d %s", rec.Code, rec.Body.String())
		}
		var d struct {
			Actors []struct {
				TopUsers []topUserRow `json:"topUsers"`
			} `json:"actors"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &d); err != nil {
			t.Fatal(err)
		}
		if len(d.Actors) == 0 || len(d.Actors[0].TopUsers) == 0 {
			t.Fatalf("no top users rendered: %s", rec.Body.String())
		}
		return len(d.Actors), d.Actors[0].TopUsers[0].Hits
	}

	n, hits := topUser()
	if n != 2 || count() != 1 || hits != 1 || len(gotIDs[0]) != 2 {
		t.Fatalf("cold: actors %d calls %d hits %d ids %v", n, count(), hits, gotIDs)
	}
	if _, hits = topUser(); count() != 1 || hits != 1 {
		t.Fatalf("second request inside the TTL reached the store: calls %d", count())
	}

	s.actorUsers.expire(actorUsersTTL)
	if _, hits = topUser(); hits != 1 {
		t.Fatalf("expired entry not served stale: hits %d", hits)
	}
	s.bg.wait()
	if count() != 2 {
		t.Fatalf("expired read started %d fetches in total, want 2", count())
	}
	if _, hits = topUser(); hits != 2 || count() != 2 {
		t.Fatalf("refreshed value not served: hits %d calls %d", hits, count())
	}

	mu.Lock()
	fail = true
	mu.Unlock()
	s.actorUsers.expire(actorUsersTTL)
	topUser()
	s.bg.wait()
	if _, hits = topUser(); hits != 2 {
		t.Fatalf("a failed refresh replaced the last-good list: hits %d", hits)
	}

	before := count()
	s.bg.stop()
	s.actorUsers.expire(actorUsersTTL)
	topUser()
	s.bg.wait()
	if count() != before {
		t.Fatal("a refresh started after shutdown")
	}
}
