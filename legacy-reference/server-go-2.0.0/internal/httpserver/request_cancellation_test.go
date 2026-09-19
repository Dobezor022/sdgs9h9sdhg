package httpserver

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"
)

func TestRequestCanceledFromOperationError(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/v1/chats", nil)
	if !requestCanceled(req, context.Canceled) {
		t.Fatal("expected context.Canceled to be treated as a canceled request")
	}
	if !requestCanceled(req, context.DeadlineExceeded) {
		t.Fatal("expected context.DeadlineExceeded to be treated as a canceled request")
	}
}

func TestRequestCanceledFromRequestContext(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/v1/chats", nil)
	ctx, cancel := context.WithCancel(req.Context())
	cancel()
	req = req.WithContext(ctx)
	if !requestCanceled(req, errors.New("database query interrupted")) {
		t.Fatal("expected canceled request context to be detected")
	}
}

func TestRequestCanceledReturnsFalseForLiveRequest(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/v1/chats", nil)
	if requestCanceled(req, errors.New("database unavailable")) {
		t.Fatal("live request must not be treated as canceled")
	}
}
