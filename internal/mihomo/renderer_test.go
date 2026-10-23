package mihomo

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/turnout-gateway/turnout-gateway/internal/config"
	"github.com/turnout-gateway/turnout-gateway/internal/subscribe"
	"gopkg.in/yaml.v3"
)

func newTestRenderer(t *testing.T) *Renderer {
	t.Helper()
	cfg := config.DataPlaneConfig{
		// Use t.TempDir so Write's atomic-rename path is writable in tests.
		ConfigPath: filepath.Join(t.TempDir(), "config.yaml"),
		LogLevel:   "info",
	}
	cfg.ApplyDefaults()
	r := NewRenderer(cfg).WithNode(config.NodeConfig{
		ClientSubnet: "10.1.2.0/24",
		IngressIP:    "10.1.2.1",
		EgressIface:  "ens18",
	})
	r.cfg.TUN.Enabled = true
	return r
}

func sampleOutbounds() []subscribe.Outbound {
	return []subscribe.Outbound{
		// trojan, no transport, simple TLS
		{
			"type": "trojan", "tag": "ash/🇺🇸US-IEPL-01",
			"server": "t7m2q9x4r8kap3-y6.edg3.org", "server_port": 32512,
			"password": "secret",
			"tls": map[string]any{
				"enabled": true, "server_name": "cas.baidu.com",
				"insecure": true,
			},
		},
		// vless+reality+utls (the bug-trigger case)
		{
			"type": "vless", "tag": "ctc-02/US-C30-01",
			"server": "us01.example.xyz", "server_port": 10050,
			"uuid": "ca70116e-e0b5-4736-8ec8-2a02cbd03a84",
			"flow": "xtls-rprx-vision", "packet_encoding": "xudp",
			"tls": map[string]any{
				"enabled": true, "server_name": "d1--ov-gotcha07.bilivideo.com",
				"reality": map[string]any{
					"enabled":    true,
					"public_key": "aGEQwyDcq--GiXgn5j5jmj5yhbbpMKIrpBtJxLkGIng",
					"short_id":   "a1b2c3d4e5f67890",
				},
				"utls": map[string]any{"enabled": true, "fingerprint": "firefox"},
			},
		},
		// vmess + ws transport
		{
			"type": "vmess", "tag": "yuyun/SG-01",
			"server": "vm.example.com", "server_port": 443,
			"uuid": "11111111-2222-3333-4444-555555555555", "alter_id": 0,
			"security": "auto",
			"tls":      map[string]any{"enabled": true, "server_name": "vm.example.com"},
			"transport": map[string]any{
				"type": "ws", "path": "/ws",
				"headers": map[string]any{"Host": "vm.example.com"},
			},
		},
		// hysteria2 (outside US — should NOT match NodePattern)
		{
			"type": "hysteria2", "tag": "yuyun/JP-Tokyo-01",
			"server": "jp.example.com", "server_port": 443,
			"password": "pwd",
			"tls":      map[string]any{"enabled": true, "server_name": "jp.example.com"},
		},
		// ss (US match)
		{
			"type": "shadowsocks", "tag": "cyberguard/🇺🇸 US-01",
			"server": "us.cg.example.com", "server_port": 8388,
			"method":   "aes-256-gcm",
			"password": "ss-pwd",
		},
		// internal types — must be filtered out
		{"type": "selector", "tag": "out-fake"},
		{"type": "urltest", "tag": "auto-fake"},
		{"type": "direct", "tag": "direct"},
	}
}

func TestRenderer_OverseasMode(t *testing.T) {
	r := newTestRenderer(t)
	r.cfg.URLTest.NodePattern = `美国|🇺🇸|\bUS`

	body, err := r.Write(sampleOutbounds())
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	var doc map[string]any
	if err := yaml.Unmarshal(body, &doc); err != nil {
		t.Fatalf("output not valid yaml: %v\n%s", err, body)
	}

	// Top-level keys
	for _, k := range []string{"mode", "log-level", "external-controller",
		"mixed-port", "dns", "tun", "sniffer", "proxies", "proxy-groups",
		"rule-providers", "rules"} {
		if _, ok := doc[k]; !ok {
			t.Errorf("missing top-level key %q", k)
		}
	}

	// proxies — should have 5 (3 internal types filtered)
	proxies, _ := doc["proxies"].([]any)
	if len(proxies) != 5 {
		t.Errorf("proxies count = %d, want 5", len(proxies))
	}

	// proxy-groups: out, default-pool, pin
	groups, _ := doc["proxy-groups"].([]any)
	if len(groups) != 3 {
		t.Fatalf("proxy-groups count = %d, want 3", len(groups))
	}
	gNames := []string{}
	var usp map[string]any
	for _, g := range groups {
		m, _ := g.(map[string]any)
		gNames = append(gNames, m["name"].(string))
		if m["name"] == "default-pool" {
			usp = m
		}
	}
	if usp == nil {
		t.Fatal("default-pool group missing")
	}
	if usp["type"] != "load-balance" {
		t.Errorf("default-pool type = %v, want load-balance", usp["type"])
	}
	if usp["strategy"] != "consistent-hashing" {
		t.Errorf("default-pool strategy = %v, want consistent-hashing", usp["strategy"])
	}
	pool, _ := usp["proxies"].([]any)
	// Pattern matches 3 of 5: ash IEPL-01 (US), ctc-02 US-C30-01,
	// cyberguard 🇺🇸 US-01. yuyun JP and yuyun SG-01 don't match.
	if len(pool) != 3 {
		t.Errorf("default-pool members = %d, want 3", len(pool))
	}

	// Rules — overseas mode ends with MATCH,out
	rules, _ := doc["rules"].([]any)
	last, _ := rules[len(rules)-1].(string)
	if last != "MATCH,out" {
		t.Errorf("last rule = %q, want MATCH,out", last)
	}
	hasGeositeCN := false
	for _, ru := range rules {
		if s, _ := ru.(string); strings.Contains(s, "RULE-SET,geosite-cn,DIRECT") {
			hasGeositeCN = true
		}
	}
	if !hasGeositeCN {
		t.Error("missing geosite-cn DIRECT rule")
	}

	// rule-providers — 2 (geosite-cn, geoip-cn)
	rp, _ := doc["rule-providers"].(map[string]any)
	if len(rp) != 2 {
		t.Errorf("rule-providers count = %d, want 2 (overseas mode)", len(rp))
	}
	if _, ok := rp["geosite-cn"]; !ok {
		t.Error("rule-providers missing geosite-cn")
	}

	// TUN
	tun, _ := doc["tun"].(map[string]any)
	if tun["enable"] != true {
		t.Errorf("tun.enable = %v, want true", tun["enable"])
	}
	if tun["auto-route"] != false {
		t.Error("tun.auto-route MUST be false (turnout-nft manages routing)")
	}
	dev, _ := tun["device"].(string)
	if len(dev) > 15 {
		t.Errorf("tun.device %q too long (%d > 15 IFNAMSIZ-1)", dev, len(dev))
	}
}

func TestRenderer_WhitelistMode(t *testing.T) {
	r := newTestRenderer(t)
	r.cfg.URLTest.NodePattern = `美国|🇺🇸|\bUS`
	r.cfg.Route.Mode = "whitelist"
	r.cfg.Route.Whitelist = config.WhitelistConfig{
		Geosites:     config.StringList{"geosite-anthropic", "geosite-openai"},
		Geoips:       config.StringList{"geoip-telegram"},
		DomainSuffix: []string{"claude.ai", "cursor.com"},
		IPCIDR:       []string{"149.154.0.0/16"},
	}

	body, err := r.Write(sampleOutbounds())
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	var doc map[string]any
	_ = yaml.Unmarshal(body, &doc)

	rules, _ := doc["rules"].([]any)
	last, _ := rules[len(rules)-1].(string)
	if last != "MATCH,DIRECT" {
		t.Errorf("whitelist final rule = %q, want MATCH,DIRECT", last)
	}
	want := map[string]bool{
		"RULE-SET,geosite-anthropic,out":         false,
		"RULE-SET,geosite-openai,out":            false,
		"RULE-SET,geoip-telegram,out,no-resolve": false,
		"DOMAIN-SUFFIX,claude.ai,out":            false,
		"DOMAIN-SUFFIX,cursor.com,out":           false,
		"IP-CIDR,149.154.0.0/16,out,no-resolve":  false,
	}
	for _, ru := range rules {
		s, _ := ru.(string)
		if _, ok := want[s]; ok {
			want[s] = true
		}
	}
	for k, seen := range want {
		if !seen {
			t.Errorf("missing whitelist rule %q", k)
		}
	}

	// rule-providers should now include WL tags
	rp, _ := doc["rule-providers"].(map[string]any)
	for _, tag := range []string{"geosite-cn", "geoip-cn",
		"geosite-anthropic", "geosite-openai", "geoip-telegram"} {
		if _, ok := rp[tag]; !ok {
			t.Errorf("rule-providers missing %q in whitelist mode", tag)
		}
	}
}

func TestRenderer_VlessRealityRoundtrip(t *testing.T) {
	// Critical: tls.utls.fingerprint must round-trip back to client-fingerprint
	// in the emitted Clash proxy entry. This is the production bug we fixed
	// on the parser side; the renderer must preserve it the other direction.
	r := newTestRenderer(t)
	r.cfg.URLTest.NodePattern = ""

	body, err := r.Write(sampleOutbounds())
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	var doc map[string]any
	_ = yaml.Unmarshal(body, &doc)

	proxies, _ := doc["proxies"].([]any)
	var vless map[string]any
	for _, p := range proxies {
		m, _ := p.(map[string]any)
		if m["type"] == "vless" {
			vless = m
			break
		}
	}
	if vless == nil {
		t.Fatal("no vless proxy in output")
	}
	if vless["client-fingerprint"] != "firefox" {
		t.Errorf("client-fingerprint = %v, want firefox", vless["client-fingerprint"])
	}
	if _, ok := vless["reality-opts"].(map[string]any); !ok {
		t.Error("vless missing reality-opts")
	}
	if vless["servername"] != "d1--ov-gotcha07.bilivideo.com" {
		t.Errorf("vless servername = %v", vless["servername"])
	}
}

func TestRenderer_EmptyPoolFallsBackToDirect(t *testing.T) {
	r := newTestRenderer(t)
	r.cfg.URLTest.NodePattern = "ZZZZ-NEVER-MATCHES"

	// With NO outbounds — bootstrap path. Pool is empty.
	body, err := r.Write(nil)
	if err != nil {
		t.Fatalf("Write empty: %v", err)
	}
	var doc map[string]any
	_ = yaml.Unmarshal(body, &doc)

	groups, _ := doc["proxy-groups"].([]any)
	// Should collapse to single 'out' selector → DIRECT
	if len(groups) != 1 {
		t.Errorf("empty bootstrap want 1 group, got %d", len(groups))
	}
	g, _ := groups[0].(map[string]any)
	if g["name"] != "out" {
		t.Errorf("group[0].name = %v, want out", g["name"])
	}
	pl, _ := g["proxies"].([]any)
	if len(pl) != 1 || pl[0] != "DIRECT" {
		t.Errorf("bootstrap group proxies = %v, want [DIRECT]", pl)
	}
}

// TestRenderer_RedirHostNoFakeIP guards the 2026-07-06 switch from fake-ip
// to redir-host. Under redir-host every domain resolves to its real IP, so
// the whole default-hijack machinery must be gone: no enhanced-mode fake-ip,
// no fake-ip-range, no fake-ip-filter. This is the fix for the recurring
// failure where a hostname missing from fake-ip-filter got a 198.18.x.x and
// then timed out on DIRECT/probe dial — intranet services (ai.corp.example.com,
// 2026-06-05) and, worst, every node health probe when a subscription
// provider's node domain was missed (11us.quandao.com, 2026-07-06:
// all nodes alive=False because mihomo dialed the fake IP).
func TestRenderer_RedirHostNoFakeIP(t *testing.T) {
	r := newTestRenderer(t)
	// Suffixes that used to require a fake-ip-filter carve-out. Under
	// redir-host they need no carve-out at all — assert none is emitted.
	r.cfg.DNS.FakeIPSkipSuffixes = []string{
		"corp.example.com",
		".internal.example.com",
		"+.intra.local",
	}
	body, err := r.Write(sampleOutbounds())
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	var doc map[string]any
	_ = yaml.Unmarshal(body, &doc)
	dns, _ := doc["dns"].(map[string]any)

	if dns["enhanced-mode"] != "redir-host" {
		t.Errorf("dns.enhanced-mode = %v, want redir-host", dns["enhanced-mode"])
	}
	if _, has := dns["fake-ip-filter"]; has {
		t.Error("dns.fake-ip-filter must be absent under redir-host (nothing is hijacked)")
	}
	if _, has := dns["fake-ip-range"]; has {
		t.Error("dns.fake-ip-range must be absent under redir-host")
	}

	// store-fake-ip has no meaning under redir-host — must be false.
	exp, _ := doc["experimental"].(map[string]any)
	cf, _ := exp["cache-file"].(map[string]any)
	if cf["store-fake-ip"] != false {
		t.Errorf("experimental.cache-file.store-fake-ip = %v, want false", cf["store-fake-ip"])
	}
}

// TestRenderer_SnifferEnabled guards the production fix from 2026-06-06:
// without sniffer, Chrome's DoH-acquired real IPs reach mihomo's TUN as raw
// IPs, geosite rules don't match, and load-balance hashes by dst IP — so a
// single Google session spreads across multiple proxy nodes and trips
// Google's session-anomaly response (the "Use secure DNS" diagnostic).
// sing-box has had the equivalent (sniff + sniff_override_destination) since
// day one. This test pins the sniffer block on so a future cleanup pass
// can't regress it silently.
func TestRenderer_SnifferEnabled(t *testing.T) {
	r := newTestRenderer(t)
	body, err := r.Write(sampleOutbounds())
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	var doc map[string]any
	_ = yaml.Unmarshal(body, &doc)

	sn, ok := doc["sniffer"].(map[string]any)
	if !ok {
		t.Fatal("missing sniffer block")
	}
	if sn["enable"] != true {
		t.Errorf("sniffer.enable = %v, want true", sn["enable"])
	}
	if sn["override-destination"] != true {
		t.Error("sniffer.override-destination MUST be true (else dst stays raw IP, geosite never matches)")
	}
	if sn["parse-pure-ip"] != true {
		t.Error("sniffer.parse-pure-ip MUST be true (the DoH-bypass case is exactly pure IP)")
	}

	sniff, _ := sn["sniff"].(map[string]any)
	for _, proto := range []string{"TLS", "HTTP", "QUIC"} {
		if _, ok := sniff[proto]; !ok {
			t.Errorf("sniffer.sniff missing %s entry", proto)
		}
	}
}

// TestRenderer_DNSNameserverPolicy guards the 2026-06-06 DNS refactor:
// dropped fallback / fallback-filter (parallel-fan-out resolution) in favor
// of nameserver-policy (domain-keyed direct routing). Mirror of sing-box's
// `{rule_set: [geosite-cn], server: local}; final: remote`.
//
// Invariants:
//   - default nameserver = proxyDoH (not cnDoH) — overseas resolves through proxy
//   - nameserver-policy["rule-set:geosite-cn"] = cnDoH — CN domains short-circuit
//   - each fake-ip-skip suffix appears as "+.<suf>" in policy → cnDoH so
//     intranet domains (corp.example.com etc.) resolve via the right side
//   - no `fallback` / `fallback-filter` keys (otherwise we're paying for
//     parallel queries again)
//   - proxy-server-nameserver = cnDoH only (airport-node hostnames must
//     resolve direct, not through the proxy we're trying to set up), and
//     no proxy-server-nameserver-policy unless the operator named suffixes
func TestRenderer_DNSNameserverPolicy(t *testing.T) {
	r := newTestRenderer(t)
	r.cfg.DNS.CNDoH = []string{"https://doh.pub/dns-query"}
	r.cfg.DNS.ProxyDoH = []string{"tls://1.1.1.1:853"}
	r.cfg.DNS.FakeIPSkipSuffixes = []string{"corp.example.com", ".internal.example.com"}

	body, err := r.Write(sampleOutbounds())
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	var doc map[string]any
	_ = yaml.Unmarshal(body, &doc)
	dns, _ := doc["dns"].(map[string]any)

	// fallback gone
	if _, has := dns["fallback"]; has {
		t.Error("dns.fallback must be removed (defeats nameserver-policy savings)")
	}
	if _, has := dns["fallback-filter"]; has {
		t.Error("dns.fallback-filter must be removed")
	}

	// default nameserver = proxyDoH
	ns, _ := dns["nameserver"].([]any)
	if len(ns) != 1 || ns[0] != "tls://1.1.1.1:853" {
		t.Errorf("dns.nameserver = %v, want [tls://1.1.1.1:853] (proxyDoH default)", ns)
	}

	// proxy-server-nameserver = cnDoH only.
	//
	// It briefly (2026-08-12, commit 86aacc8) also carried a plain-UDP
	// upstream from DNS.NodeResolver. That was reverted: psn upstreams race
	// in parallel and NXDOMAIN is not an error in that path, so appending a
	// healthy upstream does not rescue a DoH frontend returning NXDOMAIN
	// (measured: 10/10 dials still failed). It also silently promoted the
	// 4x-faster UDP upstream to de facto primary for every node hostname.
	// The scoped replacement is proxy-server-nameserver-policy, asserted
	// below.
	psn, _ := dns["proxy-server-nameserver"].([]any)
	if len(psn) != 1 || psn[0] != "https://doh.pub/dns-query" {
		t.Errorf("proxy-server-nameserver = %v, want [https://doh.pub/dns-query] (cnDoH only)", psn)
	}
	// With no node_resolver_suffixes configured, no policy block at all —
	// the default config must contain no plain-UDP resolution path.
	if _, has := dns["proxy-server-nameserver-policy"]; has {
		t.Error("proxy-server-nameserver-policy must be absent when no suffixes are configured")
	}
	// psn must never contain proxyDoH — that recurses through the proxy
	// whose server hostname we are trying to resolve.
	for _, u := range psn {
		for _, p := range r.cfg.DNS.ProxyDoH {
			if u == p {
				t.Errorf("proxy-server-nameserver contains proxyDoH %q — recursion risk", p)
			}
		}
	}

	// nameserver-policy keys
	pol, _ := dns["nameserver-policy"].(map[string]any)
	if pol == nil {
		t.Fatal("dns.nameserver-policy missing")
	}
	wantKeys := []string{
		"rule-set:geosite-cn",
		"+.corp.example.com",
		"+.internal.example.com",
	}
	for _, k := range wantKeys {
		v, ok := pol[k]
		if !ok {
			t.Errorf("nameserver-policy missing key %q", k)
			continue
		}
		list, _ := v.([]any)
		if len(list) != 1 || list[0] != "https://doh.pub/dns-query" {
			t.Errorf("nameserver-policy[%q] = %v, want cnDoH list", k, v)
		}
	}
}

// Sanity: rendered yaml must round-trip through yaml unmarshal without error.
// Sanity: rendered yaml must round-trip through yaml unmarshal without error.
func TestRenderer_YAMLValid(t *testing.T) {
	r := newTestRenderer(t)
	r.cfg.URLTest.Interval = 90 * time.Second
	body, err := r.Write(sampleOutbounds())
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(body, &doc); err != nil {
		t.Fatalf("invalid yaml: %v\n---\n%s", err, body)
	}
	if !strings.Contains(string(body), "load-balance") {
		t.Error("expected 'load-balance' in rendered output")
	}
}

// TestRenderer_NamedPool covers the openai-pool path (1.1): a pool that
// gates on probes should produce (a) a load-balance group named after the
// pool, (b) the probe-out selector + turnout-probe listener, (c) rules
// routing the pool's rule_sets to the pool instead of `out`.
func TestRenderer_NamedPool(t *testing.T) {
	r := newTestRenderer(t)
	r.cfg.URLTest.NodePattern = `美国|🇺🇸|\bUS`
	r.cfg.Route.Mode = "whitelist"
	r.cfg.Route.Whitelist = config.WhitelistConfig{
		Geosites: config.StringList{"geosite-openai", "geosite-github"},
	}
	r = r.WithPools([]config.PoolConfig{{
		Name:            "openai-pool",
		RequiresPassing: []string{"chatgpt.com"},
		RuleSets:        []string{"geosite-openai"},
	}})

	body, err := r.Write(sampleOutbounds())
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(body, &doc); err != nil {
		t.Fatalf("invalid yaml: %v\n%s", err, body)
	}

	// (a) openai-pool group exists, type load-balance.
	groups, _ := doc["proxy-groups"].([]any)
	var openai, probeOut map[string]any
	for _, g := range groups {
		m, _ := g.(map[string]any)
		switch m["name"] {
		case "openai-pool":
			openai = m
		case "probe-out":
			probeOut = m
		}
	}
	if openai == nil {
		t.Fatal("openai-pool group missing")
	}
	if openai["type"] != "load-balance" {
		t.Errorf("openai-pool type = %v, want load-balance", openai["type"])
	}
	// (b) probe-out selector + turnout-probe listener.
	if probeOut == nil {
		t.Error("probe-out selector group missing (pool gates on probes)")
	}
	listeners, _ := doc["listeners"].([]any)
	if len(listeners) == 0 {
		t.Fatal("listeners block missing (expected turnout-probe)")
	}
	l0, _ := listeners[0].(map[string]any)
	if l0["name"] != "turnout-probe" || l0["proxy"] != "probe-out" {
		t.Errorf("listener[0] = %v, want turnout-probe pinned to probe-out", l0)
	}

	// (c) rules: geosite-openai → openai-pool; geosite-github → out.
	rules, _ := doc["rules"].([]any)
	wantOpenAI, wantGithub := false, false
	for _, ru := range rules {
		s, _ := ru.(string)
		if s == "RULE-SET,geosite-openai,openai-pool" {
			wantOpenAI = true
		}
		if s == "RULE-SET,geosite-github,out" {
			wantGithub = true
		}
	}
	if !wantOpenAI {
		t.Error("missing rule RULE-SET,geosite-openai,openai-pool")
	}
	if !wantGithub {
		t.Error("missing rule RULE-SET,geosite-github,out (non-pooled tag should still route to out)")
	}
}

// TestRenderer_PoolMembersOverride checks RenderWithPools wires explicit
// member lists into the named pool group.
func TestRenderer_PoolMembersOverride(t *testing.T) {
	r := newTestRenderer(t)
	r.cfg.URLTest.NodePattern = ""
	r = r.WithPools([]config.PoolConfig{{
		Name:            "openai-pool",
		RequiresPassing: []string{"chatgpt.com"},
		RuleSets:        []string{"geosite-openai"},
	}})

	// Pick a real tag from sampleOutbounds.
	members := map[string][]string{"openai-pool": {"ash/🇺🇸US-IEPL-01"}}
	body, err := r.RenderWithPools(sampleOutbounds(), nil, nil, members)
	if err != nil {
		t.Fatalf("RenderWithPools: %v", err)
	}
	var doc map[string]any
	_ = yaml.Unmarshal(body, &doc)
	groups, _ := doc["proxy-groups"].([]any)
	for _, g := range groups {
		m, _ := g.(map[string]any)
		if m["name"] == "openai-pool" {
			pl, _ := m["proxies"].([]any)
			if len(pl) != 1 || pl[0] != "ash/🇺🇸US-IEPL-01" {
				t.Errorf("openai-pool members = %v, want [ash/🇺🇸US-IEPL-01]", pl)
			}
			return
		}
	}
	t.Fatal("openai-pool group not found")
}

// TestRenderer_PerTerminal covers "one terminal, one egress": with
// load_balance.per_terminal + whitelist, domain whitelist hits dispatch to
// the perterm sub-rule, which slices the client subnet per-/32 to default-pool
// members. IP whitelist stays on `out`. Also checks gvisor stack flips when
// requested.
func TestRenderer_PerTerminal(t *testing.T) {
	r := newTestRenderer(t)
	r.cfg.URLTest.NodePattern = `美国|🇺🇸|\bUS`
	r.cfg.TUN.Stack = "gvisor"
	r.cfg.Route.Mode = "whitelist"
	r.cfg.Route.Whitelist = config.WhitelistConfig{
		Geosites: config.StringList{"geosite-openai"},
		Geoips:   config.StringList{"geoip-telegram"},
	}
	r = r.WithLoadBalance(true)
	// small subnet → few host rules
	r.node.ClientSubnet = "10.1.2.0/29" // 6 usable hosts

	body, err := r.Write(sampleOutbounds())
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(body, &doc); err != nil {
		t.Fatalf("invalid yaml: %v\n%s", err, body)
	}

	// gvisor stack + mtu 1500
	tun, _ := doc["tun"].(map[string]any)
	if tun["stack"] != "gvisor" {
		t.Errorf("tun.stack = %v, want gvisor", tun["stack"])
	}
	if tun["mtu"] != 1500 {
		t.Errorf("tun.mtu = %v, want 1500 under gvisor", tun["mtu"])
	}

	// whitelist domain hit → SUB-RULE,(RULE-SET,geosite-openai),perterm
	// geoip → ALSO via perterm, keeping no-resolve inside the condition.
	// Sending it to `out` (default-pool, consistent-hashing by destination)
	// spread one terminal's IP-matched flows across every egress.
	rules, _ := doc["rules"].([]any)
	var sawDomainSub, sawGeoipSub bool
	for _, ru := range rules {
		s, _ := ru.(string)
		if s == "SUB-RULE,(RULE-SET,geosite-openai),perterm" {
			sawDomainSub = true
		}
		if s == "SUB-RULE,(RULE-SET,geoip-telegram,no-resolve),perterm" {
			sawGeoipSub = true
		}
		if strings.HasSuffix(s, ","+outSelector+",no-resolve") || strings.HasSuffix(s, ","+outSelector) {
			t.Errorf("per-terminal on, but %q bypasses perterm", s)
		}
	}
	if !sawDomainSub {
		t.Error("expected domain whitelist to dispatch via perterm sub-rule")
	}
	if !sawGeoipSub {
		t.Error("expected geoip whitelist to dispatch via perterm sub-rule with no-resolve")
	}

	// sub-rules.perterm: SRC-IP-CIDR slices for the 6 hosts + MATCH,default-pool
	sub, _ := doc["sub-rules"].(map[string]any)
	pt, _ := sub["perterm"].([]any)
	if len(pt) < 2 {
		t.Fatalf("perterm sub-rule too short: %v", pt)
	}
	srcCount := 0
	for _, e := range pt {
		if s, _ := e.(string); strings.HasPrefix(s, "SRC-IP-CIDR,") {
			srcCount++
		}
	}
	if srcCount != 6 {
		t.Errorf("perterm SRC-IP-CIDR rules = %d, want 6 (/29 usable hosts)", srcCount)
	}
	if last, _ := pt[len(pt)-1].(string); last != "MATCH,default-pool" {
		t.Errorf("perterm last rule = %q, want MATCH,default-pool", last)
	}
}

// TestRenderer_WithRoutingMembers covers manual-mode pool pinning: with
// WithRoutingMembers set, perterm SRC-IP-CIDR rules use ONLY those members
// (HRW pool = restricted set), regardless of how many candidates exist in
// the subscription. This is the path PoolMode=manual takes — the operator's
// PoolMembers list is the routing pool, even if the full default-pool group has
// more nodes (kept wide for probing only).
func TestRenderer_WithRoutingMembers(t *testing.T) {
	r := newTestRenderer(t)
	r.cfg.URLTest.NodePattern = `美国|🇺🇸|\bUS`
	r.cfg.Route.Mode = "whitelist"
	r.cfg.Route.Whitelist = config.WhitelistConfig{
		Geosites: config.StringList{"geosite-openai"},
	}
	r = r.WithLoadBalance(true)
	r.node.ClientSubnet = "10.1.2.0/29" // 6 usable hosts

	manualPool := []string{"ash/🇺🇸US-IEPL-01", "cyberguard/🇺🇸 US-01"}
	r = r.WithRoutingMembers(manualPool)

	body, err := r.Write(sampleOutbounds())
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(body, &doc); err != nil {
		t.Fatalf("invalid yaml: %v", err)
	}

	sub, _ := doc["sub-rules"].(map[string]any)
	pt, _ := sub["perterm"].([]any)
	if len(pt) < 2 {
		t.Fatalf("perterm sub-rule too short: %v", pt)
	}
	// Every SRC-IP-CIDR target must be a fb-<ip> fallback group.
	for _, e := range pt {
		s, _ := e.(string)
		if !strings.HasPrefix(s, "SRC-IP-CIDR,") {
			continue
		}
		// SRC-IP-CIDR,<ip>/32,fb-<ip>
		parts := strings.Split(s, ",")
		if len(parts) != 3 {
			t.Fatalf("malformed perterm rule: %q", s)
		}
		if !strings.HasPrefix(parts[2], "fb-") {
			t.Errorf("perterm rule target %q should be a fb-<ip> group", parts[2])
		}
	}

	// Verify the fb-<ip> proxy-groups exist and only contain manual-pool
	// members (HRW-ordered). With 2 manual members + fallback depth 2,
	// every fb group should have exactly 2 members from manualPool.
	groups, _ := doc["proxy-groups"].([]any)
	manualSet := map[string]bool{manualPool[0]: true, manualPool[1]: true}
	fbGroupsFound := 0
	for _, g := range groups {
		m, _ := g.(map[string]any)
		name, _ := m["name"].(string)
		if !strings.HasPrefix(name, "fb-") {
			continue
		}
		fbGroupsFound++
		if m["type"] != "fallback" {
			t.Errorf("group %s type = %v, want fallback", name, m["type"])
		}
		proxies, _ := m["proxies"].([]any)
		for _, p := range proxies {
			ps, _ := p.(string)
			if !manualSet[ps] {
				t.Errorf("fb group %s contains %q, not in manual pool %v", name, ps, manualPool)
			}
		}
	}
	if fbGroupsFound == 0 {
		t.Error("expected at least one fb-<ip> fallback group, found none")
	}
}

// TestHRWStability: removing a node only reassigns IPs that were on it.
func TestHRWStability(t *testing.T) {
	members := []string{"nodeA", "nodeB", "nodeC", "nodeD"}
	hosts := []string{"10.1.2.5", "10.1.2.6", "10.1.2.7", "10.1.2.8", "10.1.2.9"}
	before := map[string]string{}
	for _, h := range hosts {
		before[h] = hrwPick(h, members)
	}
	// Drop nodeB.
	reduced := []string{"nodeA", "nodeC", "nodeD"}
	for _, h := range hosts {
		now := hrwPick(h, reduced)
		if before[h] != "nodeB" && now != before[h] {
			t.Errorf("host %s moved from %s to %s but its node wasn't removed",
				h, before[h], now)
		}
		if now == "nodeB" {
			t.Errorf("host %s still assigned to removed nodeB", h)
		}
	}
}

// TestRenderer_PerTerminalWithPool verifies that probe-gated pool rule_sets
// route through pool-specific perterm sub-rules (perterm-openai-pool with
// openai-pool members only), not the generic perterm (all default-pool members).
// TestRenderer_PerTerminalNamedPoolUnified verifies that with per-terminal
// fallback groups, named-pool rule_sets (openai-pool etc.) route through
// the SAME generic perterm sub-rule as everything else — not a per-pool
// variant. Per-class fan-out is the anti-pattern the previous (now-
// removed) perterm-<poolname> branch caused; this test pins the new
// behavior so it can't regress.
func TestRenderer_PerTerminalNamedPoolUnified(t *testing.T) {
	r := newTestRenderer(t)
	r.cfg.URLTest.NodePattern = ""
	r.cfg.Route.Mode = "whitelist"
	r.cfg.Route.Whitelist = config.WhitelistConfig{
		Geosites: config.StringList{"geosite-openai", "geosite-github"},
	}
	r = r.WithPools([]config.PoolConfig{{
		Name:            "openai-pool",
		RequiresPassing: []string{"openai-api"},
		RuleSets:        []string{"geosite-openai"},
	}}).WithLoadBalance(true)
	r.node.ClientSubnet = "10.1.2.0/29"
	// Even with a probe-gated openai-pool, per-terminal mode should NOT
	// emit a perterm-openai-pool sub-rule.
	r.poolMembers = map[string][]string{
		"openai-pool": {"ash/🇺🇸US-IEPL-01"},
	}

	body, err := r.Write(sampleOutbounds())
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	var doc map[string]any
	_ = yaml.Unmarshal(body, &doc)

	rules, _ := doc["rules"].([]any)
	sub, _ := doc["sub-rules"].(map[string]any)

	// Must NOT exist: perterm-openai-pool variant.
	if _, ok := sub["perterm-openai-pool"]; ok {
		t.Error("perterm-openai-pool sub-rule should not exist (per-class fan-out is the anti-pattern)")
	}

	// geosite-openai and geosite-github should both route through
	// the same generic perterm sub-rule.
	var sawOpenaiPerterm, sawGithubPerterm bool
	for _, ru := range rules {
		s, _ := ru.(string)
		if s == "SUB-RULE,(RULE-SET,geosite-openai),perterm" {
			sawOpenaiPerterm = true
		}
		if s == "SUB-RULE,(RULE-SET,geosite-github),perterm" {
			sawGithubPerterm = true
		}
		// Negative: must not route through perterm-openai-pool.
		if strings.Contains(s, "perterm-openai-pool") {
			t.Errorf("rule references removed perterm-openai-pool: %q", s)
		}
	}
	if !sawOpenaiPerterm {
		t.Error("geosite-openai should route through the unified perterm sub-rule")
	}
	if !sawGithubPerterm {
		t.Error("geosite-github should route through the unified perterm sub-rule")
	}
}

// TestRenderer_DNSWhitelistSplit pins the whitelist-mode DNS model that
// diverted-DNS hijack depends on: once every office lookup lands on this
// node, only names we will actually proxy may resolve through the pool.
//
//   - default nameserver flips to cnDoH (DIRECT traffic gets domestic/CDN-
//     local answers, and lookups do not consume airport bandwidth)
//   - each whitelisted geosite and domain_suffix → proxyDoH
//   - geosite-cn and intranet suffixes keep cnDoH even when a whitelist
//     entry overlaps them (rules route those DIRECT first)
//   - geoip whitelist entries contribute nothing (IP sets name no domains)
func TestRenderer_DNSWhitelistSplit(t *testing.T) {
	r := newTestRenderer(t)
	r.cfg.DNS.CNDoH = []string{"https://doh.pub/dns-query"}
	r.cfg.DNS.ProxyDoH = []string{"tls://1.1.1.1:853"}
	r.cfg.DNS.FakeIPSkipSuffixes = []string{"corp.example.com"}
	r.SetWhitelist("whitelist", config.WhitelistConfig{
		Geosites:     config.StringList{"geosite-google", "geosite-openai"},
		Geoips:       config.StringList{"geoip-telegram"},
		DomainSuffix: []string{"claude.ai", "corp.example.com"},
	})

	body, err := r.Write(sampleOutbounds())
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	var doc map[string]any
	_ = yaml.Unmarshal(body, &doc)
	dns, _ := doc["dns"].(map[string]any)

	ns, _ := dns["nameserver"].([]any)
	if len(ns) != 1 || ns[0] != "https://doh.pub/dns-query" {
		t.Errorf("whitelist mode: dns.nameserver = %v, want [cnDoH]", ns)
	}

	pol, _ := dns["nameserver-policy"].(map[string]any)
	want := map[string]string{
		"rule-set:geosite-google": "tls://1.1.1.1:853",
		"rule-set:geosite-openai": "tls://1.1.1.1:853",
		"+.claude.ai":             "tls://1.1.1.1:853",
		"rule-set:geosite-cn":     "https://doh.pub/dns-query",
		// overlap: intranet suffix stays domestic
		"+.corp.example.com": "https://doh.pub/dns-query",
	}
	for k, up := range want {
		got, ok := pol[k].([]any)
		if !ok || len(got) != 1 || got[0] != up {
			t.Errorf("nameserver-policy[%q] = %v, want [%s]", k, pol[k], up)
		}
	}
	if _, has := pol["rule-set:geoip-telegram"]; has {
		t.Error("geoip rule-sets must not appear in nameserver-policy")
	}
}

// Ad blocking is one REJECT line per rule-set, and their position is
// load-bearing: mihomo matches top-down, so a line after geosite-cn would
// never see CN-hosted ad domains. Each provider must also be emitted with the
// right format — text for the two community lists, mrs for the MetaCubeX one.
func TestRules_AdBlockPrecedesCNDirect(t *testing.T) {
	r := newTestRenderer(t)
	r.cfg.Route.AdBlock = true

	rules, _ := r.buildRules(sampleOutbounds())
	idxCN := -1
	for i, line := range rules {
		if strings.HasPrefix(line, "RULE-SET,"+rsGeositeCN+",DIRECT") {
			idxCN = i
		}
	}
	if idxCN < 0 {
		t.Fatalf("CN-direct rule missing (test premise broken): %v", rules)
	}

	for _, rs := range AdRuleSets {
		want := "RULE-SET," + rs.Tag + ",REJECT"
		idx := -1
		for i, line := range rules {
			if line == want {
				idx = i
			}
		}
		if idx < 0 {
			t.Fatalf("ad rule %q missing from rules: %v", want, rules)
		}
		if idx > idxCN {
			t.Errorf("ad rule %q at %d must precede CN-direct at %d", rs.Tag, idx, idxCN)
		}
	}

	rp := r.buildRuleProviders()
	for _, rs := range AdRuleSets {
		p, ok := rp[rs.Tag].(map[string]any)
		if !ok {
			t.Errorf("provider %q not emitted while the switch is on", rs.Tag)
			continue
		}
		if p["format"] != rs.Format {
			t.Errorf("provider %q format = %v, want %s", rs.Tag, p["format"], rs.Format)
		}
		if path, _ := p["path"].(string); !strings.HasSuffix(path, rs.File) {
			t.Errorf("provider %q path = %v, want suffix %s", rs.Tag, p["path"], rs.File)
		}
	}
}

func TestRules_AdBlockOffEmitsNothing(t *testing.T) {
	r := newTestRenderer(t)
	rules := mustRules(t, r)
	rp := r.buildRuleProviders()
	for _, rs := range AdRuleSets {
		for _, line := range rules {
			if strings.Contains(line, rs.Tag) {
				t.Fatalf("ad rule emitted while the switch is off: %q", line)
			}
		}
		if _, ok := rp[rs.Tag]; ok {
			t.Errorf("ad provider %q emitted while the switch is off", rs.Tag)
		}
	}
}

func mustRules(t *testing.T, r *Renderer) []string {
	t.Helper()
	rules, _ := r.buildRules(sampleOutbounds())
	return rules
}

func poolBool(b bool) *bool { return &b }

// TestRenderer_ClassPoolPerTerminal covers the dual-class model: the default
// class keeps the unified perterm over the global pool (Asia), while a class
// pool with node_pattern + per_terminal gets its own fb-<pool>-* groups and
// perterm-<pool> sub-rule (US).
func TestRenderer_ClassPoolPerTerminal(t *testing.T) {
	r := newTestRenderer(t)
	r.cfg.URLTest.NodePattern = `日本|JP|SG`
	r.cfg.Route.Mode = "whitelist"
	r.cfg.Route.Whitelist = config.WhitelistConfig{
		Geosites: config.StringList{"geosite-openai", "geosite-google", "geosite-youtube"},
	}
	r = r.WithPools([]config.PoolConfig{{
		Name:         "ai-pool",
		NodePattern:  `美国|🇺🇸|\bUS`,
		Size:         2,
		PerTerminal:  poolBool(true),
		RuleSets:     []string{"geosite-openai"},
		DomainSuffix: []string{"gemini.google.com"},
	}}).WithLoadBalance(true)
	r.node.ClientSubnet = "10.1.2.0/29" // 6 hosts keeps the YAML small

	body, err := r.Write(sampleOutbounds())
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(body, &doc); err != nil {
		t.Fatalf("invalid yaml: %v\n%s", err, body)
	}

	us := map[string]bool{
		"ash/🇺🇸US-IEPL-01":    true,
		"ctc-02/US-C30-01":    true,
		"cyberguard/🇺🇸 US-01": true,
	}
	groups, _ := doc["proxy-groups"].([]any)
	var aiPool map[string]any
	aiFB, defaultFB := 0, 0
	for _, g := range groups {
		m, _ := g.(map[string]any)
		name, _ := m["name"].(string)
		switch {
		case name == "ai-pool":
			aiPool = m
		case strings.HasPrefix(name, "fb-ai-pool-"):
			aiFB++
			pl, _ := m["proxies"].([]any)
			if len(pl) != 2 {
				t.Errorf("%s has %d proxies, want 2", name, len(pl))
			}
			for _, p := range pl {
				if !us[p.(string)] {
					t.Errorf("%s member %v is not a US node", name, p)
				}
			}
		case strings.HasPrefix(name, "fb-"):
			defaultFB++
			pl, _ := m["proxies"].([]any)
			if len(pl) != 2 {
				t.Errorf("%s has %d proxies, want 2", name, len(pl))
			}
			for _, p := range pl {
				if us[p.(string)] {
					t.Errorf("default %s member %v must be an Asia node", name, p)
				}
			}
		}
	}
	if aiPool == nil {
		t.Fatal("ai-pool group missing")
	}
	if aiPool["type"] != "load-balance" {
		t.Errorf("ai-pool type = %v, want load-balance", aiPool["type"])
	}
	for _, p := range aiPool["proxies"].([]any) {
		if !us[p.(string)] {
			t.Errorf("ai-pool member %v is not a US node", p)
		}
	}
	if aiFB == 0 {
		t.Error("no fb-ai-pool-* groups emitted")
	}
	if defaultFB == 0 {
		t.Error("no default fb-* groups emitted")
	}

	rules, _ := doc["rules"].([]any)
	want := map[string]bool{
		"SUB-RULE,(RULE-SET,geosite-openai),perterm-ai-pool":         false,
		"SUB-RULE,(DOMAIN-SUFFIX,gemini.google.com),perterm-ai-pool": false,
		"SUB-RULE,(RULE-SET,geosite-google),perterm":                 false,
		"SUB-RULE,(RULE-SET,geosite-youtube),perterm":                false,
	}
	for _, ru := range rules {
		s, _ := ru.(string)
		if _, ok := want[s]; ok {
			want[s] = true
		}
	}
	for rule, seen := range want {
		if !seen {
			t.Errorf("missing rule %q", rule)
		}
	}

	sub, _ := doc["sub-rules"].(map[string]any)
	aiSub, _ := sub["perterm-ai-pool"].([]any)
	if len(aiSub) == 0 {
		t.Fatal("perterm-ai-pool sub-rule missing")
	}
	if last, _ := aiSub[len(aiSub)-1].(string); last != "MATCH,ai-pool" {
		t.Errorf("perterm-ai-pool last rule = %q, want MATCH,ai-pool", last)
	}
	foundAIFB := false
	for _, ru := range aiSub {
		if s, _ := ru.(string); strings.Contains(s, "fb-ai-pool-") {
			foundAIFB = true
		}
	}
	if !foundAIFB {
		t.Error("perterm-ai-pool does not reference fb-ai-pool-* groups")
	}
	defaultSub, _ := sub["perterm"].([]any)
	if len(defaultSub) == 0 {
		t.Fatal("default perterm sub-rule missing")
	}
	if last, _ := defaultSub[len(defaultSub)-1].(string); last != "MATCH,default-pool" {
		t.Errorf("default perterm last rule = %q, want MATCH,default-pool", last)
	}
}

// TestRenderer_ClassPoolShared: a class pool with per_terminal: false targets
// its load-balance group directly and emits no fb-<pool>-* groups.
func TestRenderer_ClassPoolShared(t *testing.T) {
	r := newTestRenderer(t)
	r.cfg.URLTest.NodePattern = `日本|JP|SG`
	r.cfg.Route.Mode = "whitelist"
	r.cfg.Route.Whitelist = config.WhitelistConfig{
		Geosites: config.StringList{"geosite-openai"},
	}
	r = r.WithPools([]config.PoolConfig{{
		Name:        "ai-pool",
		NodePattern: `美国|🇺🇸|\bUS`,
		PerTerminal: poolBool(false),
		RuleSets:    []string{"geosite-openai"},
	}}).WithLoadBalance(true)
	r.node.ClientSubnet = "10.1.2.0/29"

	body, err := r.Write(sampleOutbounds())
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(body, &doc); err != nil {
		t.Fatalf("invalid yaml: %v\n%s", err, body)
	}

	groups, _ := doc["proxy-groups"].([]any)
	for _, g := range groups {
		m, _ := g.(map[string]any)
		if name, _ := m["name"].(string); strings.HasPrefix(name, "fb-ai-pool-") {
			t.Errorf("shared pool emitted per-terminal group %q", name)
		}
	}
	rules := mustRules(t, r)
	found := false
	for _, ru := range rules {
		if ru == "RULE-SET,geosite-openai,ai-pool" {
			found = true
		}
		if strings.Contains(ru, "perterm-ai-pool") {
			t.Errorf("shared pool routed through a perterm sub-rule: %q", ru)
		}
	}
	if !found {
		t.Error("missing RULE-SET,geosite-openai,ai-pool")
	}
}

// TestRenderer_ClassPoolEmpty: a pattern that matches nothing renders a
// DIRECT stub (mihomo rejects an empty group) and the affected rules target
// the stub instead of a nonexistent fb group.
func TestRenderer_ClassPoolEmpty(t *testing.T) {
	r := newTestRenderer(t)
	r.cfg.URLTest.NodePattern = `日本|JP|SG`
	r.cfg.Route.Mode = "whitelist"
	r.cfg.Route.Whitelist = config.WhitelistConfig{
		Geosites: config.StringList{"geosite-openai"},
	}
	r = r.WithPools([]config.PoolConfig{{
		Name:        "ai-pool",
		NodePattern: `ZZZZ-NEVER-MATCHES`,
		PerTerminal: poolBool(true),
		RuleSets:    []string{"geosite-openai"},
	}}).WithLoadBalance(true)
	r.node.ClientSubnet = "10.1.2.0/29"

	body, err := r.Write(sampleOutbounds())
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(body, &doc); err != nil {
		t.Fatalf("invalid yaml: %v\n%s", err, body)
	}

	groups, _ := doc["proxy-groups"].([]any)
	var aiPool map[string]any
	for _, g := range groups {
		m, _ := g.(map[string]any)
		if m["name"] == "ai-pool" {
			aiPool = m
		}
		if name, _ := m["name"].(string); strings.HasPrefix(name, "fb-ai-pool-") {
			t.Errorf("empty pool emitted per-terminal group %q", name)
		}
	}
	if aiPool == nil {
		t.Fatal("ai-pool stub group missing")
	}
	if aiPool["type"] != "select" {
		t.Errorf("ai-pool type = %v, want select (DIRECT stub)", aiPool["type"])
	}
	pl, _ := aiPool["proxies"].([]any)
	if len(pl) != 1 || pl[0] != "DIRECT" {
		t.Errorf("ai-pool proxies = %v, want [DIRECT]", pl)
	}
	rules := mustRules(t, r)
	found := false
	for _, ru := range rules {
		if ru == "RULE-SET,geosite-openai,ai-pool" {
			found = true
		}
	}
	if !found {
		t.Error("missing RULE-SET,geosite-openai,ai-pool (empty pool must fall back to the stub)")
	}
}

// TestRenderer_PoolAssignmentForIP covers the API-facing per-class lookup:
// the returned HRW order must match the group members and the group name
// must carry the pool name.
func TestRenderer_PoolAssignmentForIP(t *testing.T) {
	r := newTestRenderer(t) // ClientSubnet 10.1.2.0/24 (host mode)
	r.poolMembers = map[string][]string{
		"ai-pool": {
			"ash/🇺🇸US-IEPL-01",
			"ctc-02/US-C30-01",
			"cyberguard/🇺🇸 US-01",
		},
	}
	us := map[string]bool{
		"ash/🇺🇸US-IEPL-01":    true,
		"ctc-02/US-C30-01":    true,
		"cyberguard/🇺🇸 US-01": true,
	}
	got, ok := r.PoolAssignmentForIP("10.1.2.42", "ai-pool", sampleOutbounds())
	if !ok {
		t.Fatal("expected an assignment for 10.1.2.42")
	}
	if len(got) != 2 {
		t.Fatalf("assignment = %v, want 2 members", got)
	}
	for _, n := range got {
		if !us[n] {
			t.Errorf("assignment member %q is not in ai-pool", n)
		}
	}
	if name := PoolPerTerminalGroupName("ai-pool", "10.1.2.42", "10.1.2.0/24"); name != "fb-ai-pool-10.1.2.42" {
		t.Errorf("group name = %q, want fb-ai-pool-10.1.2.42", name)
	}
	if _, ok := r.PoolAssignmentForIP("192.168.1.1", "ai-pool", sampleOutbounds()); ok {
		t.Error("assignment must be false for an IP outside client_subnet")
	}
	if _, ok := r.PoolAssignmentForIP("10.1.2.42", "nope", sampleOutbounds()); ok {
		t.Error("assignment must be false for an unknown pool")
	}
}
