package main

import (
	"context"
	"testing"
)

func TestNewCommandContextPropagatesParentCancellation(t *testing.T) {
	parent, cancelParent := context.WithCancel(context.Background())
	ctx, stop := newCommandContext(parent)
	defer stop()

	cancelParent()
	select {
	case <-ctx.Done():
	default:
		t.Fatal("command context did not propagate parent cancellation")
	}
}
