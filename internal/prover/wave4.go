package prover

import (
	"maps"
	pathpkg "path"
	"slices"
	"strings"

	"github.com/cuhawk/AegisMesh/internal/intent"
)

func validParent(domain, parent string) bool {
	p, ok := strings.CutPrefix(parent, "spiffe://"+domain)
	return ok && strings.HasPrefix(p, "/spire/agent/") && canonicalPath(p) && len(p) > len("/spire/agent/")
}

func checkFederation(in intent.Intent, workloads map[string]intent.Workload, add func(string, ...string)) map[intent.Pair]bool {
	allowed := make(map[intent.Pair]bool)
	f := in.Federation
	if f == nil {
		return allowed
	}
	if len(f.TrustDomains) < 2 || f.TrustDomains[in.TrustDomain].SPIREParent != in.SPIREParent {
		add("federation requires multiple domains and a matching local SPIRE parent", in.TrustDomain)
	}
	clusters, endpoints := make(map[string]string), make(map[string]string)
	for _, name := range slices.Sorted(maps.Keys(f.TrustDomains)) {
		td := f.TrustDomains[name]
		if !domain(name) || !label.MatchString(td.Cluster) || !validParent(name, td.SPIREParent) || !httpsEndpoint(td.BundleEndpoint) {
			add("invalid federated trust-domain binding", name, td.Cluster, td.SPIREParent, td.BundleEndpoint)
		}
		if other := clusters[td.Cluster]; other != "" {
			add("cluster bound to multiple trust domains", td.Cluster, other, name)
		}
		if other := endpoints[td.BundleEndpoint]; other != "" {
			add("bundle endpoint shared by multiple trust domains", td.BundleEndpoint, other, name)
		}
		clusters[td.Cluster], endpoints[td.BundleEndpoint] = name, name
		peers := make(map[string]bool)
		for _, peer := range td.Trusts {
			if _, exists := f.TrustDomains[peer]; !exists || peer == name || peers[peer] {
				add("invalid or duplicate bundle trust", name, peer)
			}
			peers[peer] = true
		}
	}
	for _, pair := range f.AllowReach {
		from, to := workloads[pair.From], workloads[pair.To]
		if from.ID == "" || to.ID == "" || from.Domain(in.TrustDomain) == to.Domain(in.TrustDomain) ||
			from.Tenant != to.Tenant || allowed[pair] {
			add("invalid or duplicate federated reachability grant", pair.From, pair.To)
		}
		allowed[pair] = true
	}
	return allowed
}

func checkWorkloadPolicy(in intent.Intent, w intent.Workload, add func(string, ...string)) {
	if in.Federation == nil {
		if w.TrustDomain != "" {
			add("workload trust domain requires federation", w.ID, w.TrustDomain)
		}
	} else if _, exists := in.Federation.TrustDomains[w.Domain(in.TrustDomain)]; !exists {
		add("unknown workload trust domain", w.ID, w.TrustDomain)
	}
	if w.ExecAllowlist != nil && len(w.ExecAllowlist) == 0 {
		add("empty executable allowlist", w.ID)
	}
	binaries := make(map[string]bool)
	for _, binary := range w.ExecAllowlist {
		if len(binary) > 255 || binary == "/" || !canonicalPath(binary) || pathpkg.Clean(binary) != binary || binaries[binary] {
			add("invalid or duplicate executable path", w.ID, binary)
		}
		binaries[binary] = true
	}
}
