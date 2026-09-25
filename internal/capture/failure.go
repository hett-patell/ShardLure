package capture

import (
	"context"
	"errors"
)

// captureError contains only diagnostics we own. Never unwrap an upstream
// error: url.Error, DNS, body and filesystem errors can all contain secrets.
// Preserve cancellation identity without retaining or exposing their text.
type captureError struct {
	status     string
	detail     string
	contextErr error
}

func (e *captureError) Error() string { return e.detail }
func (e *captureError) Is(target error) bool {
	return e.contextErr != nil && target == e.contextErr
}

func safeCaptureError(err error, fallback string) *captureError {
	for _, ctxErr := range []error{context.Canceled, context.DeadlineExceeded} {
		if errors.Is(err, ctxErr) {
			return &captureError{status: "failed", detail: ctxErr.Error(), contextErr: ctxErr}
		}
	}
	var known *captureError
	if errors.As(err, &known) {
		return known
	}
	return &captureError{status: "failed", detail: fallback}
}

func captureFailure(err error, fallback string) (*FetchResult, error) {
	safe := safeCaptureError(err, fallback)
	return &FetchResult{Status: safe.status, Detail: safe.detail}, safe
}

func terminalCaptureFailure(status, detail string) (*FetchResult, error) {
	return captureFailure(&captureError{status: status, detail: detail}, detail)
}
