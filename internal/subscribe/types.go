package subscribe

import (
	"strconv"
	"strings"
)

// Outbound is a single sing-box outbound config (ready to be embedded into
// the rendered sing-box config.json). Parsers normalize all subscription
// formats into this shape so the renderer is format-agnostic.
type Outbound map[string]any

// SubscriptionResult is the parsed result of one subscription URL.
type SubscriptionResult struct {
	Name      string
	Format    string
	Outbounds []Outbound
}

// UserInfo is the traffic-quota / expiry metadata an airport returns in the
// Subscription-Userinfo response header. All byte fields are in bytes;
// Expire is a unix timestamp (seconds). Zero values mean "field absent".
//
// The header is a semicolon-separated list of key=value pairs, e.g.:
//
//	upload=2345; download=6789; total=10737418240; expire=1719503114
//
// Surfaced to the control plane so operators can see when a subscription
// is about to expire or exhaust its quota without logging into the
// provider's panel.
type UserInfo struct {
	Upload   int64  `json:"upload"`   // bytes used upstream
	Download int64  `json:"download"` // bytes used downstream
	Total    int64  `json:"total"`    // quota ceiling in bytes (0 = unlimited)
	Expire   int64  `json:"expire"`   // unix seconds, 0 = no expiry / lifetime
}

// parseUserInfoHeader parses a Subscription-Userinfo response header value.
// The format is a semicolon-separated list of key=value pairs:
//
//	upload=1234; download=5678; total=10737418240; expire=1719503114
//
// Returns nil when the string is empty or none of the known keys are found.
func parseUserInfoHeader(h string) *UserInfo {
	if h == "" {
		return nil
	}
	info := &UserInfo{}
	found := false
	for _, part := range strings.Split(h, ";") {
		part = strings.TrimSpace(part)
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		if err != nil {
			continue
		}
		switch strings.TrimSpace(k) {
		case "upload":
			info.Upload = n
			found = true
		case "download":
			info.Download = n
			found = true
		case "total":
			info.Total = n
			found = true
		case "expire":
			info.Expire = n
			found = true
		}
	}
	if !found {
		return nil
	}
	return info
}

// Tag returns the sing-box tag of an outbound, or "" if missing.
func (o Outbound) Tag() string {
	if v, ok := o["tag"].(string); ok {
		return v
	}
	return ""
}

// Type returns the sing-box outbound type ("vmess" / "shadowsocks" / ...).
func (o Outbound) Type() string {
	if v, ok := o["type"].(string); ok {
		return v
	}
	return ""
}
