package notify

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/turnout-gateway/turnout-gateway/internal/config"
)

// SendPrivate must put the secret on the wire to Lark and nowhere in the
// world-readable local log.
func TestSendPrivateKeepsBodyOutOfLocalLog(t *testing.T) {
	var mu sync.Mutex
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		got += string(b)
		mu.Unlock()
		_, _ = w.Write([]byte(`{"code":0}`))
	}))
	defer srv.Close()

	logPath := filepath.Join(t.TempDir(), "notifications.log")
	n := New(config.NotificationsConfig{
		Enabled:       true,
		Lark:          config.LarkConfig{WebhookURL: srv.URL},
		LocalLogPath:  logPath,
		RetryAttempts: 1,
	}, "")
	defer n.Close()

	const secret = "ABCD-EFGH-JKLM-NPQR-STUV"
	if err := n.SendPrivate(Event{
		Time:     time.Now(),
		Severity: SeverityUrgent,
		Type:     "api_setup_code",
		Subject:  "setup code",
		Body:     "code: " + secret,
	}); err != nil {
		t.Fatalf("SendPrivate: %v", err)
	}
	mu.Lock()
	sent := got
	mu.Unlock()
	if !strings.Contains(sent, secret) {
		t.Error("secret did not reach the webhook")
	}
	logged, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(logged), secret) {
		t.Error("secret leaked into the local JSONL log")
	}
	if !strings.Contains(string(logged), "api_setup_code") || !strings.Contains(string(logged), "redacted") {
		t.Errorf("local log should record a redacted entry, got %q", logged)
	}
}

func TestSendPrivateWithoutWebhook(t *testing.T) {
	n := New(config.NotificationsConfig{}, "")
	defer n.Close()
	if err := n.SendPrivate(Event{Type: "api_setup_code", Body: "x"}); err == nil {
		t.Fatal("expected an error when no webhook is configured")
	}
}
