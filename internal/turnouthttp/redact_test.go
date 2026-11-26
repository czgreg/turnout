package turnouthttp

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestRedactURL(t *testing.T) {
	cases := map[string]string{
		"https://198.51.100.7:36666/hxvip?token=deadbeef": "https://198.51.100.7:36666/…",
		"https://sub.example/s/v2/AbCdEfSecret":           "https://sub.example/…",
		"https://sub.example/link/Qm9xYz?clash=3":         "https://sub.example/…",
		"https://user:pw@sub.example/":                    "https://sub.example",
		"https://sub.example":                             "https://sub.example",
		"https://sub.example/#frag":                       "https://sub.example/…",
		"not a url":                                       "<redacted-url>",
		"://bad":                                          "<redacted-url>",
	}
	for in, want := range cases {
		if got := RedactURL(in); got != want {
			t.Errorf("RedactURL(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestRedactErr_URLErrorKeepsTypeAndTimeout: the error http.Client.Do returns
// on a timeout quotes the full URL. After redaction the token must be gone,
// and the subscribe retry logic must still see a *url.Error that times out.
func TestRedactErr_URLErrorKeepsTypeAndTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	}))
	defer srv.Close()
	raw := srv.URL + "/s/v2/SECRETTOKEN?token=SECRET2"

	_, err := NewClient("", 50*time.Millisecond, "test").Get(raw)
	if err == nil || !strings.Contains(err.Error(), "SECRETTOKEN") {
		t.Fatalf("precondition: want a timeout error quoting the URL, got %v", err)
	}
	red := RedactErr(err, raw)
	if strings.Contains(red.Error(), "SECRET") {
		t.Errorf("redacted error still carries the token: %v", red)
	}
	var ue *url.Error
	if !errors.As(red, &ue) {
		t.Errorf("redacted error is no longer a *url.Error: %T", red)
	}
	var ne net.Error
	if !errors.As(red, &ne) || !ne.Timeout() {
		t.Errorf("redacted error no longer reports a timeout: %v", red)
	}
}

func TestRedactErr_PlainErrorKeepsTimeoutAndChain(t *testing.T) {
	raw := "https://sub.example/s/v2/SECRET"
	base := &net.DNSError{Err: "i/o timeout", Name: "sub.example", IsTimeout: true}
	wrapped := errors.New("read body from " + raw + ": " + base.Error())
	if got := RedactErr(wrapped, raw); strings.Contains(got.Error(), "SECRET") {
		t.Errorf("token not redacted: %v", got)
	}

	// A non-url.Error that quotes the URL keeps its chain.
	inner := &url.Error{Op: "Get", URL: raw, Err: base}
	outer := errorsJoin(inner)
	got := RedactErr(outer, raw)
	if strings.Contains(got.Error(), "SECRET") {
		t.Errorf("token not redacted: %v", got)
	}
	var ne net.Error
	if !errors.As(got, &ne) || !ne.Timeout() {
		t.Errorf("timeout lost through redaction: %v", got)
	}
}

func TestRedactErr_UnrelatedErrorUnchanged(t *testing.T) {
	err := errors.New("connection refused")
	if got := RedactErr(err, "https://sub.example/s/SECRET"); got != err {
		t.Errorf("an error that does not quote the URL must come back unchanged, got %v", got)
	}
	if RedactErr(nil, "https://x") != nil {
		t.Error("nil must stay nil")
	}
}

type joined struct{ err error }

func (j joined) Error() string { return "fetch: " + j.err.Error() }
func (j joined) Unwrap() error { return j.err }

func errorsJoin(err error) error { return joined{err} }
