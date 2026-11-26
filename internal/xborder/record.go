// Package xborder builds one access-log record per cross-border connection
// (traffic mihomo sent out through an airport node) and ships it to a
// syslog server.
//
// Three local sources, all read-only and on the node itself:
//
//   - mihomo /connections, sampled every poll interval: connection ID,
//     start, byte counts, full proxy chain.
//   - mihomo /logs (info): one line per established connection, and the
//     only place dial failures appear. Covers connections that open and
//     close between two samples.
//   - `ss -tn`: the original destination IP of a TPROXY'd TCP connection
//     (the accepted socket's local address), which mihomo drops once
//     sniffing overrides the destination with a hostname.
//
// See docs/design-crossborder-access-log.md for the field list and the
// known limits.
package xborder

import "time"

// Schema identifies the record layout. Adding fields keeps the version;
// removing or changing the meaning of one bumps it.
const Schema = "turnout.xborder.v1"

const (
	EventClose     = "close"
	EventDialError = "dial_error"
)

// tsLayout is millisecond RFC 3339 in the node's local zone.
const tsLayout = "2006-01-02T15:04:05.000Z07:00"

type Record struct {
	Schema  string        `json:"schema"`
	Event   string        `json:"event"`
	Seq     uint64        `json:"seq"`
	TS      string        `json:"ts"`
	Gateway GatewayFields `json:"gateway"`
	Conn    ConnFields    `json:"conn"`
	Src     SrcFields     `json:"src"`
	Dst     DstFields     `json:"dst"`
	Route   RouteFields   `json:"route"`
	Egress  EgressFields  `json:"egress"`
	// Traffic is nil for dial_error: nothing was transferred.
	Traffic *TrafficFields `json:"traffic,omitempty"`
	Result  ResultFields   `json:"result"`
	Collect CollectFields  `json:"collect"`
}

type GatewayFields struct {
	Hostname string `json:"hostname"`
}

type ConnFields struct {
	// ID is mihomo's connection UUID, or a synthetic
	// log-<src_ip>-<src_port>-<unix_ms> when the connection was only seen
	// in the log stream.
	ID         string `json:"id"`
	Network    string `json:"network"`
	Start      string `json:"start"`
	End        string `json:"end,omitempty"`
	DurationMs int64  `json:"duration_ms"`
}

type SrcFields struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

type DstFields struct {
	Host      string `json:"host"`
	SniffHost string `json:"sniff_host"`
	// IP is the address the terminal originally dialed — NOT the server
	// the airport node finally reached (the node resolves the hostname
	// itself; that address is invisible here).
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

type RouteFields struct {
	Rule        string   `json:"rule"`
	RulePayload string   `json:"rule_payload"`
	Pool        string   `json:"pool"`
	Group       string   `json:"group"`
	Chains      []string `json:"chains"`
}

type EgressFields struct {
	// Node is the airport node (chains[0]). Empty for dial_error: mihomo
	// logs only the group it dialed through, not the member it picked.
	Node   string `json:"node"`
	Region string `json:"region"`
}

type TrafficFields struct {
	UpBytes   int64 `json:"up_bytes"`
	DownBytes int64 `json:"down_bytes"`
	// BytesFinal is false when the counts come from the last sample before
	// the connection closed (traffic after that sample is missing), or
	// when the connection was never sampled at all (counts are zero).
	BytesFinal bool `json:"bytes_final"`
}

type ResultFields struct {
	Status string `json:"status"`
	Error  string `json:"error"`
}

type CollectFields struct {
	// Tracked: the connection appeared in at least one /connections sample.
	Tracked bool `json:"tracked"`
	// Logged: its establish (or dial error) line was seen in /logs.
	Logged bool `json:"logged"`
}

func fmtTS(t time.Time) string { return t.Format(tsLayout) }
