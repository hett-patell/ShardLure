package actor

import (
	"context"
	"errors"

	"github.com/networkshard/shardlure/internal/store"
)

// AdvancePendingJournalSummaries advances up to batch pending journal actors
// after the cursor and returns the cursor for the next cycle, wrapping to the
// start once the end is reached.
//
// A failing actor is skipped, not retried in place: the live worker used to
// take the first batch in actor_id order and stop at the first error, so one
// actor with a persistently bad row (an unparseable first_seen, a summary row
// outliving its actor) blocked derivation for every journal actor after it,
// leaving them masked as pending with probe score 0. It is deliberately NOT
// retired to unknown_history, which is sticky: a transient database error must
// not permanently drop an actor's classification. It is retried on the next
// lap, and its error is still returned so worker health reports it.
func AdvancePendingJournalSummaries(ctx context.Context, st *store.Store, after string, batch int) (string, error) {
	ids, err := st.PendingJournalSummariesAfter(ctx, after, batch)
	if err != nil {
		return after, err
	}
	if len(ids) == 0 {
		return "", nil // wrap: the next cycle starts from the beginning
	}
	var failures []error
	for _, id := range ids {
		if _, err := st.AdvanceJournalSummary(ctx, id, 1000, NewJournalSummaryCodec()); err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return after, ctxErr
			}
			failures = append(failures, err)
		}
	}
	return ids[len(ids)-1], errors.Join(failures...)
}
