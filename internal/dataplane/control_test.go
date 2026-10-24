package dataplane

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/turnout-gateway/turnout-gateway/internal/config"
)

// hotReload's error classification decides whether Reload falls back to
// `systemctl restart`. A 4xx means the engine is up and rejected the file;
// restarting re-reads that same file and ExecStartPre's `mihomo -t` keeps the
// unit down, so 4xx must be distinguishable from a transport failure.
func TestHotReloadClassifies4xxAsRejected(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusUnauthorized} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "proxy not found", status)
		}))
		c := NewController(config.ClashAPIConfig{
			ExternalController: strings.TrimPrefix(srv.URL, "http://"),
		})

		err := c.hotReload(context.Background(), "/var/lib/turnout/mihomo/config.yaml")
		srv.Close()

		if !errors.Is(err, errConfigRejected) {
			t.Fatalf("status %d: err = %v, want errConfigRejected", status, err)
		}
	}
}

// 5xx is an unhappy engine, not a verdict on the config: it must keep the
// systemctl fallback.
func TestHotReloadDoesNotClassify5xxAsRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := NewController(config.ClashAPIConfig{
		ExternalController: strings.TrimPrefix(srv.URL, "http://"),
	})
	err := c.hotReload(context.Background(), "/var/lib/turnout/mihomo/config.yaml")
	if err == nil {
		t.Fatal("expected an error for 500")
	}
	if errors.Is(err, errConfigRejected) {
		t.Fatalf("5xx was classified as a config rejection: %v", err)
	}
}
