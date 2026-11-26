package xborder

import (
	"reflect"
	"testing"
)

func TestParseLogLine(t *testing.T) {
	cases := []struct {
		name string
		msg  string
		ok   bool
		want logLine
	}{
		{
			name: "established through per-terminal pool group",
			msg:  "[TCP] 192.0.2.10:62239 --> chat.example.com:443 match SubRules((RULE-SET,geosite-openai)) using fb-ai-pool-p-f3f7e5d79e9f[sub-a/美国_BGP_D]",
			ok:   true,
			want: logLine{
				key:  connKey{network: "tcp", srcIP: "192.0.2.10", srcPort: 62239, dstPort: 443},
				host: "chat.example.com", rule: "SubRules", rulePayload: "(RULE-SET,geosite-openai)",
				group: "fb-ai-pool-p-f3f7e5d79e9f", node: "sub-a/美国_BGP_D",
			},
		},
		{
			name: "node name with spaces and brackets",
			msg:  "[UDP] 192.0.2.10:5000 --> 203.0.113.7:443 match GeoIP(us) using fb-p-abc[sub-b/🇯🇵 日本01 [IPLC]]",
			ok:   true,
			want: logLine{
				key:  connKey{network: "udp", srcIP: "192.0.2.10", srcPort: 5000, dstPort: 443},
				host: "203.0.113.7", rule: "GeoIP", rulePayload: "us",
				group: "fb-p-abc", node: "sub-b/🇯🇵 日本01 [IPLC]",
			},
		},
		{
			name: "direct, rule without payload",
			msg:  "[TCP] 192.0.2.10:60671 --> api.example.cn:443 match Match using DIRECT",
			ok:   true,
			want: logLine{
				key:  connKey{network: "tcp", srcIP: "192.0.2.10", srcPort: 60671, dstPort: 443},
				host: "api.example.cn", rule: "Match", node: "DIRECT",
			},
		},
		{
			name: "no rule matched",
			msg:  "[TCP] 192.0.2.10:1 --> x.example:80 doesn't match any rule using default-pool[sub-a/n1]",
			ok:   true,
			want: logLine{
				key:  connKey{network: "tcp", srcIP: "192.0.2.10", srcPort: 1, dstPort: 80},
				host: "x.example", group: "default-pool", node: "sub-a/n1",
			},
		},
		{
			name: "dial error with nested parens and multi-line error",
			msg:  "[TCP] dial fb-p-1700e287fc0c (match SubRules/(RULE-SET,geosite-google)) 192.0.2.10:61877 --> mtalk.example.com:5228 error: relay.example.net:14117 connect error: dial tcp 198.51.100.4:14117: i/o timeout\ndial tcp 198.51.100.4:14117: i/o timeout",
			ok:   true,
			want: logLine{
				key:  connKey{network: "tcp", srcIP: "192.0.2.10", srcPort: 61877, dstPort: 5228},
				host: "mtalk.example.com", rule: "SubRules", rulePayload: "(RULE-SET,geosite-google)",
				group: "fb-p-1700e287fc0c", dialErr: true,
				err: "relay.example.net:14117 connect error: dial tcp 198.51.100.4:14117: i/o timeout\ndial tcp 198.51.100.4:14117: i/o timeout",
			},
		},
		{
			name: "dial error without rule",
			msg:  "[TCP] dial default-pool 192.0.2.10:7 --> a.example:443 error: timeout",
			ok:   true,
			want: logLine{
				key:  connKey{network: "tcp", srcIP: "192.0.2.10", srcPort: 7, dstPort: 443},
				host: "a.example", group: "default-pool", dialErr: true, err: "timeout",
			},
		},
		{
			name: "ipv6 source",
			msg:  "[TCP] [2001:db8::5]:4000 --> b.example:443 match DomainSuffix(example) using fb-p-1[sub/n]",
			ok:   true,
			want: logLine{
				key:  connKey{network: "tcp", srcIP: "2001:db8::5", srcPort: 4000, dstPort: 443},
				host: "b.example", rule: "DomainSuffix", rulePayload: "example", group: "fb-p-1", node: "sub/n",
			},
		},
		{name: "loopback probe is not a terminal", msg: "[TCP] 127.0.0.1:5555 --> www.example.com:443 match Match using probe-out[sub/n]"},
		{name: "special proxy line (dns-out)", msg: "[TCP] mihomo --> dns.example:443 using dns-out"},
		{name: "sniffer noise", msg: "[Sniffer] [IP] [tls] may not have any sent data, Consider adding skip"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseLogLine(tc.msg)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v (got %+v)", ok, tc.ok, got)
			}
			if ok && !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got  %+v\nwant %+v", got, tc.want)
			}
		})
	}
}

func TestRegionOf(t *testing.T) {
	cases := map[string]string{
		"sub/美国_BGP_D":      "US",
		"sub/🇨🇳 台湾01":       "TW", // mislabeled flag: name wins
		"sub/🇩🇪 德国":         "DE",
		"sub/🇯🇵 01":         "JP", // flag only
		"sub/印度尼西亚-雅加达":     "ID", // not IN
		"sub/🇮🇳印度-孟买":       "IN",
		"sub/澳大利亚-悉尼":       "AU",
		"sub/mhome":         "",
		"no-subscription-x": "",
		"sub/香港01 境外中转":     "HK",
	}
	for in, want := range cases {
		if got := regionOf(in); got != want {
			t.Errorf("regionOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPoolOf(t *testing.T) {
	pools := []string{"ai-pool-x", "ai-pool"} // longest first, as NewCollector sorts
	cases := map[string]string{
		"default-pool":       "default-pool",
		"fb-p-abc":           "default-pool",
		"fb-10-0-0-1":        "default-pool",
		"ai-pool":            "ai-pool",
		"fb-ai-pool-p-abc":   "ai-pool",
		"fb-ai-pool-x-p-abc": "ai-pool-x",
		"out":                "",
		"":                   "",
	}
	for in, want := range cases {
		if got := poolOf(in, pools); got != want {
			t.Errorf("poolOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseSS(t *testing.T) {
	out := "0      0      [::ffff:203.0.113.9]:443   [::ffff:192.0.2.10]:56208\n" +
		"0      0      198.51.100.1:443   192.0.2.11:4000\n" +
		"0      0      [2001:db8::9]:443  [2001:db8::5]:4000  users:((\"mihomo\",pid=1,fd=9))\n" +
		"garbage\n"
	got := parseSS(out)
	want := map[string]string{
		"192.0.2.10:56208":   "203.0.113.9",
		"192.0.2.11:4000":    "198.51.100.1",
		"[2001:db8::5]:4000": "2001:db8::9",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseSS = %v, want %v", got, want)
	}
	if k := srcKey("192.0.2.10", 56208); got[k] != "203.0.113.9" {
		t.Errorf("srcKey lookup %q failed", k)
	}
}
