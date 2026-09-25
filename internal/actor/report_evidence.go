package actor

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/networkshard/shardlure/internal/store"
	"github.com/networkshard/shardlure/pkg/models"
)

// ReportEvidenceForIP reclassifies only the target's recent observations.
// It never borrows counts, usernames, client fingerprints, or behaviour from
// a HASSH cluster. Missing telemetry returns zero evidence (fail closed).
func ReportEvidenceForIP(st *store.Store, a *models.Actor, now time.Time) (*models.Actor, error) {
	return ReportEvidenceForIPContext(context.Background(), st, a, now)
}

func ReportEvidenceForIPContext(ctx context.Context, st *store.Store, a *models.Actor, now time.Time) (*models.Actor, error) {
	result := &models.Actor{ID: a.ID, Source: a.Source, PrimaryIP: a.PrimaryIP}
	var features playbookFeatures
	var previousUser string
	var clientID int64
	usernameHash := newUsernameHash()
	recentCount := 0
	recentSince := now.Add(-store.RecentRateWindow)
	err := st.IterateReportEvidenceContext(ctx, a.Source, a.PrimaryIP, now.Add(-store.ReportPoolMaxAge), now, func(e *models.Event) {
		if !e.TS.Before(recentSince) {
			recentCount++
		}
		result.EventCount++
		if result.FirstSeen.IsZero() || e.TS.Before(result.FirstSeen) {
			result.FirstSeen = e.TS
		}
		if e.TS.After(result.LastSeen) {
			result.LastSeen = e.TS
		}
		// The store groups usernames, so exact dedup needs one previous value,
		// not an attacker-sized map. Hash in sorted order for builder parity.
		if e.Username != "" && e.Username != "?" && e.Username != previousUser {
			addUsernameHash(usernameHash, e.Username)
			features.add(e.Username)
			previousUser = e.Username
		}
		if a.Source == models.SourceCowrie {
			result.Flags |= CowrieEventFlags(e)
			// Preserve the first recorded nonempty banner despite username order.
			if e.SSHClient != "" && (clientID == 0 || e.ID < clientID) {
				clientID, result.SSHClient = e.ID, e.SSHClient
			}
		}
	})
	if err != nil {
		return nil, err
	}
	if result.EventCount > 0 {
		window := result.LastSeen.Sub(result.FirstSeen).Hours()
		aph := float64(result.EventCount) / max(window, minWindowHours)
		result.UniqueUsers = features.users
		if features.users > 0 {
			result.UsernameHash = hex.EncodeToString(usernameHash.Sum(nil)[:8])
		}
		result.Playbook = features.classify(aph)
		result.Intent = "unknown"
		if a.Source == models.SourceCowrie {
			stats := &CowrieStats{Flags: result.Flags}
			tunnel, payload := stats.has(models.ActorFlagTunnel), stats.has(models.ActorFlagPayload)
			deploy := stats.has(models.ActorFlagDeployCmd)
			result.Playbook = cowriePlaybook(result.Playbook, result.SSHClient,
				stats.has(models.ActorFlagAuth), stats.has(models.ActorFlagCommand), tunnel, payload)
			result.Intent = ClassifyIntent(tunnel, payload, stats.has(models.ActorFlagProbe), deploy)
			result.ProbeScore = cowrieProbeScore(stats, aph)
			result.Confidence = ConfidenceCowrieBase
			if payload || deploy {
				result.Confidence = ConfidenceCowriePayload
			}
			result.GeneratedNotes = fmt.Sprintf("%d events, %d usernames", result.EventCount, features.users)
		} else {
			result.ProbeScore = journalProbeScore(result.EventCount, aph, features.users)
			result.Confidence = ConfidenceJournalBase
			if window >= minWindowHours && aph > 100 {
				result.Confidence = ConfidenceJournalHighAPH
			}
			result.GeneratedNotes = fmt.Sprintf("%d distinct usernames", features.users)
		}
		result.DerivedCurrent = true
	}
	// Classification uses the observed seven-day evidence span. Ranking and
	// generated report comments describe the fixed recent window, not a burst
	// two days ago. A quiet day must not erase otherwise valid evidence.
	result.AttemptsPerHour = float64(recentCount) / store.RecentRateWindow.Hours()
	return result, nil
}
