// endpoint.go — ranking penalty for a failing shared server endpoint.
//
// Several airports put dozens of nodes behind one relay hostname. momo's
// "*_LL" nodes (36 of them on 10.100.6.15, 2026-11-23) all dial one relay
// hostname, a TTL-5s DNS round-robin over Aliyun HK addresses of which about
// a third were dead. mihomo re-resolves on almost every dial,
// so ~12% of connections through ANY of those nodes hung until the 5s dial
// timeout ("GitHub is slow"), while delay probes mostly landed on live
// addresses and kept the nodes at the top of the ranking (p95 ~45ms).
//
// Per node the signal is too thin to act on: 1 failed probe in 8, which the
// quadratic fail term in compositeScore prices at +78 — nowhere near enough to
// lose to a clean 400ms node. Pooled across every node on the same server
// host it is ~280 samples per round and unambiguous. Penalizing per node
// would also be pointless: the next-best replacement is another node on the
// same relay.
//
// The penalty is the expected stall a connection pays on that endpoint,
// failRate × endpointStallMs, in the same "ms-ish" units as compositeScore.
// It is applied at RANKING time (nodeLongEWMA), not fed into the EWMA:
//
//   - the 24h long EWMA would take ~2 days to move a node from ~130 to the
//     ~750 needed to lose to the alternatives; this is a current fault of a
//     shared component, not node history;
//   - the penalty disappears the round the endpoint recovers, and the
//     nodes' untouched EWMA lets them win their slots back (subject to the
//     usual swap threshold);
//   - it is continuous in the failure rate, so there is no threshold for
//     membership to flap across.
//
// Only probe history from mihomo's url-test is used — zero extra airport
// traffic.

package nodescorer

import (
	"log/slog"
	"math"
	"strings"

	"github.com/turnout-gateway/turnout-gateway/internal/subscribe"
)

const (
	// endpointStallMs is what one failed dial costs a user: mihomo's TCP
	// connect timeout (~5s) before the request errors out. Expected cost per
	// connection = failRate × endpointStallMs.
	endpointStallMs = 5000.0

	// endpointMinNodes / endpointMinProbes: below these the pooled rate is
	// either just the node's own fail rate (already priced by compositeScore)
	// or too few samples to trust. At 8-10 probes per node, 3 nodes clears
	// 20 samples comfortably.
	endpointMinNodes  = 3
	endpointMinProbes = 20
)

// serverHosts maps outbound tag → normalized server host. Outbounds without a
// server (or tag) are omitted.
func serverHosts(outbounds []subscribe.Outbound) map[string]string {
	out := make(map[string]string, len(outbounds))
	for _, o := range outbounds {
		tag := o.Tag()
		host, _ := o["server"].(string)
		host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
		if tag == "" || host == "" {
			continue
		}
		out[tag] = host
	}
	return out
}

// applyEndpointPenalties pools probe failures per server host across nodes,
// writes Endpoint / EndpointFailRate / EndpointPenalty into nodes, and
// returns tag → penalty for every node that carries one (> 0).
//
// Nodes that are dead (alive=false) or catastrophically failing
// (FailRate >= hardFailThreshold) do not contribute: that is a node-level
// failure the liveness gate already handles, and counting it would smear
// one broken port onto its healthy siblings. Unmeasured nodes contribute
// nothing either. The penalty is still applied to every node on the host,
// contributing or not, so an out-of-pool node on a broken relay cannot be
// promoted in place of the one just pushed out.
//
// PURE apart from writing into nodes.
func applyEndpointPenalties(nodes []NodeHealth, hostOf map[string]string) map[string]float64 {
	type agg struct{ nodes, probes, failed int }
	byHost := map[string]*agg{}
	for i := range nodes {
		h := &nodes[i]
		host := hostOf[h.Name]
		h.Endpoint = host
		if host == "" || h.ProbeCount == 0 || !h.Alive || h.FailRate >= hardFailThreshold {
			continue
		}
		a := byHost[host]
		if a == nil {
			a = &agg{}
			byHost[host] = a
		}
		a.nodes++
		a.probes += h.ProbeCount
		a.failed += int(math.Round(h.FailRate * float64(h.ProbeCount)))
	}

	penalties := map[string]float64{}
	for i := range nodes {
		h := &nodes[i]
		a := byHost[h.Endpoint]
		if a == nil || a.nodes < endpointMinNodes || a.probes < endpointMinProbes {
			continue
		}
		rate := float64(a.failed) / float64(a.probes)
		h.EndpointFailRate = rate
		h.EndpointPenalty = rate * endpointStallMs
		if h.EndpointPenalty > 0 {
			penalties[h.Name] = h.EndpointPenalty
		}
	}
	return penalties
}

// endpointLogPenalty is the penalty above which an endpoint is reported as
// degraded in the log — about where it starts to decide swaps (the default
// SwapThresholdScore is 100). Below it the penalty still applies, silently.
const endpointLogPenalty = 100.0

// logEndpointPenaltyChanges logs an endpoint once when its penalty crosses
// endpointLogPenalty in either direction, so an operator reading the journal
// sees why a whole relay's nodes left (or returned to) the pool without a
// line per round.
func logEndpointPenaltyChanges(prev, curr map[string]float64, nodes []NodeHealth) {
	type hostInfo struct {
		was, is float64
		nodes   int
		rate    float64
	}
	hosts := map[string]*hostInfo{}
	for _, n := range nodes {
		if n.Endpoint == "" {
			continue
		}
		hi := hosts[n.Endpoint]
		if hi == nil {
			hi = &hostInfo{}
			hosts[n.Endpoint] = hi
		}
		hi.nodes++
		hi.was = math.Max(hi.was, prev[n.Name])
		hi.is = math.Max(hi.is, curr[n.Name])
		hi.rate = math.Max(hi.rate, n.EndpointFailRate)
	}
	for host, hi := range hosts {
		switch {
		case hi.is >= endpointLogPenalty && hi.was < endpointLogPenalty:
			slog.Warn("nodescorer: shared endpoint degraded — penalizing its nodes in ranking",
				"endpoint", host, "nodes", hi.nodes, "pooled_fail_rate", hi.rate, "penalty", hi.is)
		case hi.is < endpointLogPenalty && hi.was >= endpointLogPenalty:
			slog.Info("nodescorer: shared endpoint recovered — penalty lifted",
				"endpoint", host, "nodes", hi.nodes, "pooled_fail_rate", hi.rate, "penalty", hi.is)
		}
	}
}
