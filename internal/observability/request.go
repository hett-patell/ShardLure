package observability

import (
	"context"
	"errors"
	"net/http"
)

type monitorContextKey struct{}
type requestContextKey struct{}

func WithMonitor(ctx context.Context, m *Monitor) context.Context {
	if m == nil {
		return ctx
	}
	return context.WithValue(ctx, monitorContextKey{}, m)
}
func ContextMonitor(ctx context.Context) *Monitor {
	m, _ := ctx.Value(monitorContextKey{}).(*Monitor)
	return m
}

// Request keeps one operation's closed outcome, never an endpoint, key, body or
// actor label. Missing observers are no-ops. StartHTTP is called only at Do.
type Request struct {
	m               *Monitor
	provider        Provider
	operation       Operation
	started         bool
	status          int
	transportFailed bool
}

func TraceRequest(ctx context.Context, p Provider, op Operation) (context.Context, *Request) {
	m := ContextMonitor(ctx)
	if m == nil {
		return ctx, nil
	}
	r := &Request{m: m, provider: p, operation: op}
	return context.WithValue(ctx, requestContextKey{}, r), r
}
func StartHTTP(ctx context.Context) {
	r, _ := ctx.Value(requestContextKey{}).(*Request)
	if r != nil && ctx.Err() == nil {
		r.started = true
	}
}
func HTTPResult(ctx context.Context, response *http.Response, err error) {
	r, _ := ctx.Value(requestContextKey{}).(*Request)
	if r == nil {
		return
	}
	r.transportFailed = err != nil
	if response != nil {
		r.status = response.StatusCode
	}
}
func (r *Request) Finish(err error, semantic ...Outcome) {
	if r == nil || !r.started {
		return
	}
	outcome := Success
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		outcome = Canceled
	case r.status == 401 || r.status == 403:
		outcome = Unauthorized
	case r.status == 429:
		outcome = RateLimited
	case r.transportFailed:
		outcome = TransportError
	case err != nil:
		outcome = InvalidResponse
	}
	if len(semantic) > 0 && semantic[0] >= 0 && semantic[0] < outcomeCount {
		outcome = semantic[0]
	}
	_ = r.m.ObserveProvider(r.provider, r.operation, outcome)
}
func DurableShare(ctx context.Context, p Provider, err error, n uint64) {
	if m := ContextMonitor(ctx); m != nil {
		outcome := Success
		if err != nil {
			outcome = StorageError
		}
		_ = m.ObserveDurableShare(p, outcome, n)
	}
}
