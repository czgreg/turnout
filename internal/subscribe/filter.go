package subscribe

import "strings"

// filterOutbounds drops nodes that should never reach the mihomo config:
// info-banner pseudo-nodes that many providers ship as fake outbounds
// (remaining quota, expiry, homepage URL). They'd land in the urltest
// pool and probe forever. Match by tag substring against provider conventions.
//
// It also drops client-gating pseudo-nodes: providers that refuse to serve
// a subscription to an unrecognised client emit "please use FlClash" /
// "your core does not support AnyTLS" entries instead of real proxies.
// Those are worse than banners — a banner is obviously informational, while
// these look like nodes and make NodeCount look healthy, which suppresses
// the zero_nodes fallback that would otherwise retry with a newer UA.
func filterOutbounds(in []Outbound) []Outbound {
	out, _ := filterOutboundsStats(in)
	return out
}

// filterOutboundsStats is filterOutbounds plus a count of the client-gating
// pseudo-nodes it dropped. Callers report that count so an operator can tell
// "provider served nothing" apart from "provider served warnings because it
// does not recognise our client" — the two need different actions.
func filterOutboundsStats(in []Outbound) ([]Outbound, int) {
	out := make([]Outbound, 0, len(in))
	gated := 0
	for _, o := range in {
		tag := o.Tag()
		if isBannerTag(tag) {
			continue
		}
		if isGatingHintTag(tag) {
			gated++
			continue
		}
		out = append(out, o)
	}
	return out, gated
}

// bannerSubstrings catches Chinese subscription banner conventions. Match is
// substring + case-insensitive on ASCII; CJK characters compare literally.
var bannerSubstrings = []string{
	"剩余流量", "套餐到期", "距离下次", "过期时间", "已用流量", "总流量",
	"官网", "订阅", "网址", "重置", "续费", "购买", "充值",
	"工单", "客服", "公告", "通知", "导航", "收藏",
	"重新导入", "请尝试", "节点超时", "套餐",
	"telegram", "tg频道", "tg群",
}

// gatingHintSubstrings catches client-gating pseudo-nodes. Observed in
// production 2026-10-21 on hutao: the provider returned four entries named
// after the client it wanted the user to switch to, and our parser counted
// them as four working nodes. Each phrase is something a real proxy tag
// never contains — "不支持" appears only in capability warnings.
var gatingHintSubstrings = []string{
	"请改用", "请升级到", "请升级", "请更新", "请使用",
	"内核不支持", "客户端不支持", "不支持", "版本过低", "版本太低",
}

func isBannerTag(tag string) bool {
	if tag == "" {
		return false
	}
	// Real proxy nodes don't embed URLs in their tag — providers do this to
	// advertise their site. Use as a structural fallback for tags that don't
	// match any keyword above.
	if strings.Contains(tag, "://") {
		return true
	}
	low := strings.ToLower(tag)
	for _, s := range bannerSubstrings {
		if strings.Contains(low, strings.ToLower(s)) {
			return true
		}
	}
	return false
}

func isGatingHintTag(tag string) bool {
	if tag == "" {
		return false
	}
	low := strings.ToLower(tag)
	for _, s := range gatingHintSubstrings {
		if strings.Contains(low, strings.ToLower(s)) {
			return true
		}
	}
	return false
}
