package xborder

import (
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// notOverseas are mihomo's built-in terminal outbounds. A chain ending in
// one of these did not leave through an airport node.
var notOverseas = map[string]bool{
	"DIRECT":      true,
	"REJECT":      true,
	"REJECT-DROP": true,
	"PASS":        true,
	"COMPATIBLE":  true,
}

func isOverseasNode(node string) bool { return node != "" && !notOverseas[node] }

// connKey joins a log line to a /connections entry. The client's source
// port is reused only after the previous connection on it is gone, so
// within the few seconds a log line waits to be claimed this is unique.
type connKey struct {
	network string
	srcIP   string
	srcPort int
	dstPort int
}

// logLine is one parsed mihomo connection log line.
type logLine struct {
	key         connKey
	host        string // host or IP from the "--> host:port" part
	rule        string
	rulePayload string
	group       string
	node        string
	dialErr     bool
	err         string
}

// Formats, from mihomo tunnel/tunnel.go (v1.19):
//
//	[TCP] 10.0.0.2:5000 --> example.com:443 match DomainSuffix(example.com) using grp[node]
//	[TCP] 10.0.0.2:5000 --> example.com:443 match Match using DIRECT
//	[TCP] 10.0.0.2:5000 --> example.com:443 doesn't match any rule using grp[node]
//	[TCP] dial grp (match SubRules/(RULE-SET,x)) 10.0.0.2:5000 --> example.com:443 error: ...
//	[TCP] dial grp 10.0.0.2:5000 --> example.com:443 error: ...
var (
	reMatch   = regexp.MustCompile(`^\[(TCP|UDP)\] (\S+) --> (\S+) match (.+?) using (.+)$`)
	reNoMatch = regexp.MustCompile(`^\[(TCP|UDP)\] (\S+) --> (\S+) doesn't match any rule using (.+)$`)
	reDialR   = regexp.MustCompile(`(?s)^\[(TCP|UDP)\] dial (.+?) \(match ([^/]*)/(.*?)\) (\S+) --> (\S+) error: (.*)$`)
	reDialNR  = regexp.MustCompile(`(?s)^\[(TCP|UDP)\] dial (\S+) (\S+) --> (\S+) error: (.*)$`)
)

// parseLogLine returns the connection described by a mihomo log message,
// or ok=false for anything that is not a terminal's connection line
// (DNS, sniffer, gateway-internal traffic from loopback, ...).
func parseLogLine(msg string) (logLine, bool) {
	var l logLine
	var netw, src, dst string
	switch {
	case reMatch.MatchString(msg):
		m := reMatch.FindStringSubmatch(msg)
		netw, src, dst = m[1], m[2], m[3]
		l.rule, l.rulePayload = splitRule(m[4])
		l.group, l.node = splitChain(m[5])
	case reNoMatch.MatchString(msg):
		m := reNoMatch.FindStringSubmatch(msg)
		netw, src, dst = m[1], m[2], m[3]
		l.group, l.node = splitChain(m[4])
	case reDialR.MatchString(msg):
		m := reDialR.FindStringSubmatch(msg)
		netw, src, dst = m[1], m[5], m[6]
		l.group, l.rule, l.rulePayload = m[2], m[3], m[4]
		l.dialErr, l.err = true, strings.TrimSpace(m[7])
	case reDialNR.MatchString(msg):
		m := reDialNR.FindStringSubmatch(msg)
		netw, src, dst = m[1], m[3], m[4]
		l.group = m[2]
		l.dialErr, l.err = true, strings.TrimSpace(m[5])
	default:
		return l, false
	}
	sip, sport, ok := splitAddr(src)
	if !ok {
		return l, false
	}
	// Loopback sources are the gateway's own probes through mihomo's
	// local HTTP/SOCKS inbounds, not terminal traffic.
	if a, err := netip.ParseAddr(sip); err != nil || a.IsLoopback() || a.IsUnspecified() {
		return l, false
	}
	host, dport, ok := splitAddr(dst)
	if !ok {
		return l, false
	}
	l.host = host
	l.key = connKey{network: strings.ToLower(netw), srcIP: sip, srcPort: sport, dstPort: dport}
	return l, true
}

// splitRule turns "SubRules((RULE-SET,geosite-openai))" into
// ("SubRules", "(RULE-SET,geosite-openai)") and "Match" into ("Match", "").
func splitRule(s string) (string, string) {
	i := strings.IndexByte(s, '(')
	if i < 0 || !strings.HasSuffix(s, ")") {
		return s, ""
	}
	return s[:i], s[i+1 : len(s)-1]
}

// splitChain turns mihomo's chain string into (group, node). mihomo prints
// a multi-hop chain as "last[first]" — the group the rule chose, then the
// node that carried the traffic — and a single hop as the bare name.
// Group names never contain a space or '[' (the renderer generates them),
// node names may, so only a space-free prefix counts as a group.
func splitChain(s string) (group, node string) {
	i := strings.IndexByte(s, '[')
	if i > 0 && strings.HasSuffix(s, "]") && !strings.ContainsAny(s[:i], " ") {
		return s[:i], s[i+1 : len(s)-1]
	}
	return "", s
}

// splitAddr splits "1.2.3.4:5", "[::1]:5" or "example.com:443".
func splitAddr(s string) (string, int, bool) {
	h, p, err := net.SplitHostPort(s)
	if err != nil || h == "" {
		return "", 0, false
	}
	port, err := strconv.Atoi(p)
	if err != nil || port < 0 || port > 65535 {
		return "", 0, false
	}
	return h, port, true
}

// parseSS reads `ss -Htn state established` output (columns: Recv-Q
// Send-Q Local Peer [Process]) into peer "ip:port" → local IP. For a
// socket mihomo accepted through TPROXY, the local address is the
// destination the terminal originally dialed.
func parseSS(out string) map[string]string {
	m := make(map[string]string)
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		local, err1 := netip.ParseAddrPort(f[2])
		peer, err2 := netip.ParseAddrPort(f[3])
		if err1 != nil || err2 != nil {
			continue
		}
		key := netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port()).String()
		m[key] = local.Addr().Unmap().String()
	}
	return m
}

// srcKey is the parseSS map key for a terminal endpoint.
func srcKey(ip string, port int) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ""
	}
	return netip.AddrPortFrom(a.Unmap(), uint16(port)).String()
}

// poolOf maps a proxy group to the pool it belongs to: the pool's own
// group ("ai-pool"), a per-terminal group of a named pool
// ("fb-ai-pool-p-<hash>"), or a default-class per-terminal group
// ("fb-p-<hash>", "fb-<ip>") → default-pool. Mirrors the naming in
// internal/mihomo/perterminal.go. pools must be sorted longest first so
// "fb-ai-pool-x-" is not taken for "fb-ai-".
func poolOf(group string, pools []string) string {
	if group == "default-pool" {
		return group
	}
	for _, p := range pools {
		if group == p || strings.HasPrefix(group, "fb-"+p+"-") {
			return p
		}
	}
	if strings.HasPrefix(group, "fb-") {
		return "default-pool"
	}
	return ""
}

// regionNames maps the place names airport providers put in node names to
// ISO 3166 codes. Checked before the flag emoji because providers mislabel
// flags (observed: "🇨🇳 台湾01" for a Taiwan node).
var regionNames = []struct{ name, code string }{
	// Longer names first where one contains another (印度尼西亚 ⊃ 印度).
	{"印度尼西亚", "ID"}, {"印尼", "ID"}, {"沙特阿拉伯", "SA"}, {"沙特", "SA"},
	{"澳大利亚", "AU"}, {"澳洲", "AU"}, {"哈萨克斯坦", "KZ"}, {"巴基斯坦", "PK"},
	{"哥伦比亚", "CO"}, {"马来西亚", "MY"}, {"阿联酋", "AE"}, {"迪拜", "AE"},
	{"新加坡", "SG"}, {"新西兰", "NZ"}, {"俄罗斯", "RU"}, {"乌克兰", "UA"},
	{"土耳其", "TR"}, {"阿根廷", "AR"}, {"以色列", "IL"}, {"墨西哥", "MX"},
	{"菲律宾", "PH"}, {"尼日利亚", "NG"}, {"孟加拉", "BD"}, {"爱尔兰", "IE"},
	{"意大利", "IT"}, {"西班牙", "ES"}, {"葡萄牙", "PT"}, {"加拿大", "CA"},
	{"香港", "HK"}, {"台湾", "TW"}, {"澳门", "MO"}, {"日本", "JP"},
	{"韩国", "KR"}, {"美国", "US"}, {"英国", "GB"}, {"德国", "DE"},
	{"法国", "FR"}, {"荷兰", "NL"}, {"瑞士", "CH"}, {"瑞典", "SE"},
	{"挪威", "NO"}, {"芬兰", "FI"}, {"丹麦", "DK"}, {"波兰", "PL"},
	{"巴西", "BR"}, {"智利", "CL"}, {"秘鲁", "PE"}, {"印度", "IN"},
	{"泰国", "TH"}, {"越南", "VN"}, {"柬埔寨", "KH"}, {"南非", "ZA"},
	{"埃及", "EG"}, {"奥地利", "AT"}, {"比利时", "BE"}, {"希腊", "GR"},
	{"匈牙利", "HU"}, {"捷克", "CZ"}, {"罗马尼亚", "RO"}, {"冰岛", "IS"},
}

// regionOf infers a node's country from its name; "" when it can't. Only
// the part after "<subscription>/" is examined.
func regionOf(node string) string {
	if i := strings.IndexByte(node, '/'); i >= 0 {
		node = node[i+1:]
	}
	for _, r := range regionNames {
		if strings.Contains(node, r.name) {
			return r.code
		}
	}
	// Flag emoji: two Regional Indicator Symbols (U+1F1E6..U+1F1FF).
	rs := []rune(node)
	for i := 0; i+1 < len(rs); i++ {
		a, b := rs[i]-0x1F1E6, rs[i+1]-0x1F1E6
		if a >= 0 && a < 26 && b >= 0 && b < 26 {
			return string([]rune{'A' + a, 'A' + b})
		}
	}
	return ""
}
