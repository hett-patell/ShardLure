package urlhaus

import (
	"context"
	"errors"
	"fmt"

	"github.com/networkshard/shardlure/internal/intel/intelutil"
)

// ProviderError kinds. A closed set: the kind decides the error text and the
// operator-facing summary, so no upstream free text can choose either.
const (
	// ProviderErrorHTTP is a non-2xx response (other than an auth failure).
	ProviderErrorHTTP = "http"
	// ProviderErrorTransport is a dial/read failure. Cancellation keeps its
	// identity instead of becoming a ProviderError.
	ProviderErrorTransport = "transport"
	// ProviderErrorInvalidResponse is a body we could not parse.
	ProviderErrorInvalidResponse = "invalid_response"
	// ProviderErrorRejected is a structured provider refusal. The provider's
	// own status word is deliberately not retained.
	ProviderErrorRejected = "rejected"
)

// ProviderError is a client failure carrying only bounded, log-safe fields.
// The endpoint, API key, request body and every provider-supplied word are
// never retained (the submission client's contract, pinned by
// TestSubmitRejectsNonOKStatusWithoutProviderText). The kind plus the HTTP
// status still distinguishes the failure classes an operator acts on. Before
// this, a rejected submission surfaced only as "some submissions failed — see
// server logs", and the server logged only "operation_failed" — the cause was
// invisible.
type ProviderError struct {
	Operation  string // "submit" or "lookup"
	Kind       string
	HTTPStatus int
}

func (e *ProviderError) Error() string {
	switch e.Kind {
	case ProviderErrorHTTP:
		return fmt.Sprintf("urlhaus: %s returned HTTP %d", e.Operation, e.HTTPStatus)
	case ProviderErrorTransport:
		// The transport error may name the endpoint or a proxy; keep it out.
		return fmt.Sprintf("urlhaus: %s failed", e.Operation)
	case ProviderErrorRejected:
		return fmt.Sprintf("urlhaus: %s rejected", e.Operation)
	default:
		return fmt.Sprintf("urlhaus: invalid %s response", e.Operation)
	}
}

// ErrRejectedEntries means URLhaus accepted the batch shape but refused some
// entries in it; those are not recorded and retry on the next run.
var ErrRejectedEntries = errors.New("urlhaus: submission contained rejected entries")

// FailureSummary returns a fixed, operator-readable summary of an error
// returned by this package, for dashboard and CLI logs. It names our own
// categories and nothing else: no URL, key, path, request body or upstream
// free text. Errors this package did not produce are a local (ledger/storage)
// failure, which is what Share joins alongside a provider error when a ledger
// write fails.
func FailureSummary(err error) string {
	var pe *ProviderError
	switch {
	case err == nil:
		return ""
	case errors.As(err, &pe):
		lookup := pe.Operation == "lookup"
		switch pe.Kind {
		case ProviderErrorHTTP:
			if lookup {
				return fmt.Sprintf("the listing check returned HTTP %d", pe.HTTPStatus)
			}
			return fmt.Sprintf("URLhaus returned HTTP %d", pe.HTTPStatus)
		case ProviderErrorTransport:
			if lookup {
				return "could not reach URLhaus for the listing check"
			}
			return "could not reach URLhaus"
		case ProviderErrorRejected:
			if lookup {
				return "URLhaus rejected the listing check"
			}
			return "URLhaus rejected the submission"
		default:
			if lookup {
				return "the listing check returned an unreadable response"
			}
			return "URLhaus returned an unreadable response"
		}
	case errors.Is(err, ErrUnauthorized):
		return "abuse.ch rejected the Auth-Key"
	case errors.Is(err, ErrMissingAPIKey):
		return "no abuse.ch Auth-Key configured"
	case errors.Is(err, ErrRejectedEntries):
		return "URLhaus rejected some entries in the batch"
	case errors.Is(err, intelutil.ErrResponseTooLarge):
		return "URLhaus returned an oversized response"
	case errors.Is(err, ErrNoEntries):
		return "nothing to submit"
	case errors.Is(err, context.Canceled):
		return "request was canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "request timed out"
	}
	return "local storage error"
}
