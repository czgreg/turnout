// Package turnouthttp is the canonical HTTP-client factory for any turnout-gateway
// outbound that talks to an OVERSEAS host (anything not on 127.0.0.0/8, the
// office client subnet, or other LAN ranges).
//
// # Why this package exists
//
// turnout-gateway runs co-located with the mihomo data plane. A direct
// `net.Dial` to an overseas host like raw.githubusercontent.com egresses
// through the host's main interface — straight into the GFW, where the
// connection is reset or blackholed. Result: indefinite timeout. This was
// the root cause of the subscribe-fetcher outage memo'd as
// the upstream forwarding-node quirks memo (pitfall #6).
//
// (Under the former fake-ip DNS mode this bit harder: the host resolver
// handed back 198.18.x.x for overseas names and the direct dial went
// nowhere. Since the 2026-07-06 redir-host switch the resolver returns a
// real IP, but a direct dial still hits the GFW — routing through the
// pool is required either way.)
//
// # The pattern
//
// Dial THROUGH the loopback HTTP proxy mihomo exposes
// (TurnoutInternalProxyURL = http://127.0.0.1:11080). Mihomo resolves the
// host via its own DNS and egresses through default-pool to a real overseas
// peer, past the GFW.
//
// Two failure modes argue for "proxy with direct fallback", not "proxy
// only":
//
//  1. Bootstrap. mihomo isn't ready yet at process startup; the first
//     refresh-on-startup must succeed even before the data plane is up.
//     Falling back to direct dial during that window has a chance of
//     working (the fake-IP cache may not yet be populated for this host)
//     and is strictly better than failing.
//
//  2. Data-plane crash. mihomo restart cycle should not freeze every
//     turnout-gateway outbound; a direct fallback at least lets refresh
//     attempts run while the operator investigates.
//
// # The rule
//
// Anything in this codebase that does `&http.Client{}` for an OVERSEAS
// host is a bug — the direct dial hits the GFW and times out. **Use
// NewClient always.** The only allowed exception is loopback-only HTTP
// (clash-api on 127.0.0.1:9090, turnout-internal HTTP inbounds on
// 127.0.0.1:1108x): local, no need to egress through the pool.
//
// # Body rewinding
//
// The fallback retries the same `*http.Request` against a different
// transport. This is safe for GET/HEAD (idempotent, no body). For POST
// or other body-having requests, callers should set `req.GetBody` so
// the underlying RoundTripper can rewind — Go's standard library
// supports this when the body is built from `bytes.Buffer` /
// `strings.Reader` etc. via `http.NewRequest`. None of turnout-gateway's
// current callers POST through this path; this note is a reminder for
// future use.
package turnouthttp

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// NewClient returns an *http.Client that dials through the turnout-internal
// mihomo proxy at proxyURL, transparently falling back to a direct dial
// when the proxy errors at the transport layer (refused, dial timeout,
// TLS handshake failure, etc).
//
// HTTP-status errors (4xx/5xx) are NOT retried via fallback — the proxy
// successfully relayed bytes to the upstream and a different egress
// path won't change the upstream's mind. Caller checks `resp.StatusCode`
// after `Do()` returns nil error, as with any standard *http.Client.
//
// proxyURL = "" degrades to a single direct-dial client (no fallback).
// Used by tests, CLIs, and bootstrap rendering where no data plane is
// expected to exist.
//
// timeout caps the entire round-trip (connect + headers + body). 0 ⇒
// 30s default. Should be tuned per use case — subscription fetches use
// 30-60s, ruleset fetches use 60s, telemetry probes can be 5-10s.
//
// label is interpolated into fallback-warning slog lines (e.g. "subscribe",
// "rulesets") so journal
// scrapes can attribute failures back to the originating module without
// reading goroutine stacks.
func NewClient(proxyURL string, timeout time.Duration, label string) *http.Client {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	if label == "" {
		label = "turnouthttp"
	}
	direct := &http.Transport{}
	if proxyURL == "" {
		return &http.Client{Timeout: timeout, Transport: direct}
	}
	u, err := url.Parse(proxyURL)
	if err != nil {
		slog.Warn("turnouthttp: invalid proxy url, degrading to direct",
			"label", label, "url", proxyURL, "err", err)
		return &http.Client{Timeout: timeout, Transport: direct}
	}
	via := &http.Transport{Proxy: http.ProxyURL(u)}
	return &http.Client{
		Timeout: timeout,
		Transport: &fallbackRT{
			primary:  via,
			fallback: direct,
			label:    label,
		},
	}
}

// fallbackRT is a RoundTripper that tries primary first; on transport-
// layer errors it retries on fallback. HTTP-status responses (any
// 1xx/2xx/3xx/4xx/5xx) are returned to the caller as-is — those are
// upstream answers, not transport failures.
type fallbackRT struct {
	primary  http.RoundTripper
	fallback http.RoundTripper
	label    string
}

func (r *fallbackRT) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := r.primary.RoundTrip(req)
	if err == nil {
		return resp, nil
	}
	if !isTransportError(err) {
		return resp, err
	}
	// Neither the URL nor err is logged as-is: subscription URLs carry their
	// token, and net/http quotes the full URL inside err. See RedactURL.
	raw := req.URL.String()
	slog.Warn("turnouthttp: primary failed, retrying via direct",
		"label", r.label, "url", RedactURL(raw), "err", RedactErr(err, raw))
	// Body rewind is the caller's responsibility via req.GetBody — see
	// package doc. GET/HEAD have no body so this is moot for current
	// callers.
	return r.fallback.RoundTrip(req)
}

// isTransportError filters out errors that should NOT trigger fallback.
// Currently we treat ALL non-nil errors from a RoundTripper as transport
// errors (no response was produced) — that's the standard contract:
// http.RoundTripper returns either (resp, nil) or (nil, err); a non-
// nil err always means we never got bytes back from the upstream. The
// helper exists so future changes (e.g. respecting context cancellation
// without retry) have a place to land.
func isTransportError(err error) bool {
	if err == nil {
		return false
	}
	// Don't retry context cancellation — the caller deliberately gave up.
	// Deadline-exceeded IS retried because the budget might cover the
	// fallback path and retry-once is cheaper than failing the call.
	if errors.Is(err, context.Canceled) {
		return false
	}
	return true
}

// RedactURL reduces a URL to scheme://host for logs, events and error
// strings. Subscription URLs carry their credential in the query
// (?token=...) or in the path (/link/<token>, /s/v2/<token>), and there is
// no reliable way to tell which segment is the secret, so both go. Userinfo
// goes too. Those strings reach the journal, GET /api/subscriptions
// (health_err) and the Lark webhook — on 6.15 a hutao 429 printed its full
// path token into all three (2026-10-24).
//
// An unparseable input yields a fixed placeholder rather than the input.
func RedactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "<redacted-url>"
	}
	out := u.Scheme + "://" + u.Host
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		out += "/…"
	}
	return out
}

// RedactErr returns err with every occurrence of raw replaced by
// RedactURL(raw). A top-level *url.Error (what http.Client.Do returns) is
// copied with its URL rewritten and its inner error kept, so errors.As and
// net.Error.Timeout() still work on the result; anything else that quotes
// raw is flattened to its redacted text. err is returned unchanged when it
// does not contain raw.
func RedactErr(err error, raw string) error {
	if err == nil || raw == "" || !strings.Contains(err.Error(), raw) {
		return err
	}
	red := RedactURL(raw)
	if ue, ok := err.(*url.Error); ok {
		cp := *ue
		cp.URL = strings.ReplaceAll(cp.URL, raw, red)
		if cp.Err != nil && strings.Contains(cp.Err.Error(), raw) {
			cp.Err = redactedErr{msg: strings.ReplaceAll(cp.Err.Error(), raw, red), orig: cp.Err}
		}
		return &cp
	}
	return redactedErr{msg: strings.ReplaceAll(err.Error(), raw, red), orig: err}
}

// redactedErr carries a redacted message but keeps the original error for
// errors.Is / errors.As and Timeout(), so callers that classify errors (the
// subscribe timeout retry, context checks) see through the redaction.
type redactedErr struct {
	msg  string
	orig error
}

func (e redactedErr) Error() string { return e.msg }
func (e redactedErr) Unwrap() error { return e.orig }
func (e redactedErr) Timeout() bool {
	var t interface{ Timeout() bool }
	return errors.As(e.orig, &t) && t.Timeout()
}
