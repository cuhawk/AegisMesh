package prover

import (
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/cuhawk/AegisMesh/internal/intent"
)

var modelID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var objectName = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$`)

func canonicalPath(value string) bool {
	parts := strings.Split(value, "/")
	return strings.HasPrefix(value, "/") && path.MatchString(value) &&
		!slices.Contains(parts, ".") && !slices.Contains(parts, "..")
}

func httpsEndpoint(value string) bool {
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || !domain(u.Hostname()) || u.User != nil ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" ||
		(u.Path != "" && !canonicalPath(u.Path)) {
		return false
	}
	if u.Host == u.Hostname() {
		return true
	}
	port, err := strconv.ParseUint(u.Port(), 10, 16)
	return err == nil && port > 0
}

func checkIdentity(in intent.Intent, add func(string, ...string)) map[string]bool {
	if in.JWTAuthority != nil && (!httpsEndpoint(in.JWTAuthority.Issuer) || !httpsEndpoint(in.JWTAuthority.JWKSURI)) {
		add("invalid JWT-SVID authority", in.JWTAuthority.Issuer, in.JWTAuthority.JWKSURI)
	}
	tools := make(map[string]bool)
	for _, w := range in.Workloads {
		if w.ToolScope != "" {
			tools[w.ID] = true
			if !label.MatchString(w.ToolScope) || in.JWTAuthority == nil || w.Ingress {
				add("invalid tool isolation", w.ID, w.ToolScope)
			}
		}
		if c := w.Claims; c != nil {
			delegatorPath, sameDomain := strings.CutPrefix(c.DelegatorSub, "spiffe://"+w.Domain(in.TrustDomain))
			if in.JWTAuthority == nil || !modelID.MatchString(c.ModelID) || !sameDomain ||
				!canonicalPath(delegatorPath) || delegatorPath == "/" || c.DelegatorSub == w.SPIFFEID(in.TrustDomain) {
				add("invalid model identity claims", w.ID, c.ModelID, c.DelegatorSub)
			}
			seen := make(map[string]bool)
			if len(c.ToolScopes) == 0 {
				add("missing model tool scopes", w.ID)
			}
			for _, scope := range c.ToolScopes {
				if !label.MatchString(scope) || seen[scope] {
					add("invalid model tool scope", w.ID, scope)
				}
				seen[scope] = true
			}
		}
	}
	return tools
}

type gatewayMatch struct {
	gateway, backend, method, path string
	port                           int
}

func checkGateway(in intent.Intent, workloads map[string]intent.Workload, allowed map[gatewayMatch]bool, add func(string, ...string)) {
	type grantKey struct{ from, to, service string }
	grants := make(map[grantKey]intent.ReferenceGrant)
	names := make(map[string]bool)
	for _, g := range in.ReferenceGrants {
		key := grantKey{g.FromNamespace, g.Namespace, g.Service}
		name := g.Namespace + "/" + g.Name
		if !label.MatchString(g.Name) || !label.MatchString(g.Namespace) || !label.MatchString(g.FromNamespace) ||
			!label.MatchString(g.Service) || g.Namespace == g.FromNamespace ||
			grants[key].Name != "" || names[name] {
			add("invalid or duplicate ReferenceGrant", name, g.FromNamespace, g.Service)
			continue
		}
		grants[key], names[name] = g, true
	}
	names = make(map[string]bool)
	matches := make(map[[5]string]string)
	services := make(map[[2]string]string)
	used := make(map[grantKey]bool)
	for _, r := range in.HTTPRoutes {
		gateway, backend := workloads[r.Gateway], workloads[r.Backend]
		name := r.Namespace + "/" + r.Name
		if !label.MatchString(r.Name) || !label.MatchString(r.Namespace) || !label.MatchString(r.Listener) ||
			!domain(r.Hostname) || !label.MatchString(r.Service) || gateway.ID == "" ||
			backend.ID == "" || gateway.ID == backend.ID || !gateway.Ingress ||
			in.Cluster(gateway) != in.Cluster(backend) || gateway.Tenant != backend.Tenant || backend.ToolScope != "" ||
			!allowed[gatewayMatch{r.Gateway, r.Backend, r.Method, r.Path, r.Port}] {
			add("HTTPRoute lacks a verified gateway backend edge", name, r.Gateway, r.Backend)
			continue
		}
		routeID := in.Cluster(gateway) + "/" + name
		if names[routeID] {
			add("duplicate HTTPRoute", name)
		}
		names[routeID] = true
		match := [5]string{r.Gateway, r.Listener, r.Hostname, r.Method, r.Path}
		if other := matches[match]; other != "" {
			add("conflicting HTTPRoute match", other, name)
		}
		matches[match] = name
		service := backend.Namespace + "/" + r.Service
		serviceID := [2]string{in.Cluster(backend), service}
		if other := services[serviceID]; other != "" && other != backend.ID {
			add("conflicting HTTPRoute backend identity", service, other, backend.ID)
		}
		services[serviceID] = backend.ID
		if r.Namespace != backend.Namespace {
			key := grantKey{r.Namespace, backend.Namespace, r.Service}
			if grants[key].Name == "" {
				add("HTTPRoute lacks a matching ReferenceGrant", name, service)
			}
			used[key] = true
		}
	}
	for _, g := range in.ReferenceGrants {
		key := grantKey{g.FromNamespace, g.Namespace, g.Service}
		if grants[key] == g && !used[key] {
			add("unused ReferenceGrant", g.Namespace+"/"+g.Name, g.FromNamespace, g.Service)
		}
	}
}

func parsePrefix(raw string) (netip.Prefix, bool) {
	p, err := netip.ParsePrefix(raw)
	return p, err == nil && p == p.Masked() && !p.Addr().Is4In6()
}

func prefixEnd(p netip.Prefix) netip.Addr {
	b := p.Addr().AsSlice()
	for bit := p.Bits(); bit < len(b)*8; bit++ {
		b[bit/8] |= 1 << (7 - bit%8)
	}
	end, _ := netip.AddrFromSlice(b)
	return end
}

func covered(prefix netip.Prefix, except []netip.Prefix) bool {
	current, end := prefix.Addr(), prefixEnd(prefix)
	for _, p := range except {
		if p.Contains(current) {
			last := prefixEnd(p)
			if last.Compare(end) >= 0 {
				return true
			}
			current = last.Next()
		}
	}
	return false
}

func checkIsolation(inventory *intent.IsolationInventory, workloads map[string]intent.Workload, add func(string, ...string)) {
	if inventory == nil {
		return
	}
	for _, admin := range inventory.EnvoyAdmins {
		bind, err := netip.ParseAddrPort(admin.Address)
		loopback := err == nil && bind.Port() != 0 && bind.Addr().Zone() == "" && bind.Addr().Unmap().IsLoopback()
		socket, unix := strings.CutPrefix(admin.Address, "unix:")
		isolatedSocket := unix && canonicalPath(socket) && !strings.HasSuffix(socket, "/")
		if workloads[admin.Workload].ID == "" || !admin.Isolated || (!loopback && !isolatedSocket) {
			add("unisolated Envoy admin listener", admin.Workload, admin.Address)
		}
	}
	destinations := make(map[string]string)
	for _, sync := range inventory.TLSSecretSyncs {
		source := sync.SourceNamespace + "/" + sync.SourceName
		target := sync.TargetNamespace + "/" + sync.TargetName
		if !label.MatchString(sync.SourceNamespace) || !label.MatchString(sync.TargetNamespace) ||
			!objectName.MatchString(sync.SourceName) || !objectName.MatchString(sync.TargetName) ||
			len(sync.SourceName) > 253 || len(sync.TargetName) > 253 {
			add("invalid TLS secret sync", source, target)
		}
		if old := destinations[target]; old != "" && old != source {
			add("TLS secret sync name collision", old, source, target)
		}
		destinations[target] = source
	}
	var cluster []netip.Prefix
	for _, raw := range inventory.ClusterCIDRs {
		p, ok := parsePrefix(raw)
		if !ok || p.Bits() == 0 {
			add("invalid cluster CIDR", raw)
			continue
		}
		cluster = append(cluster, p)
	}
	for _, block := range inventory.IPBlocks {
		p, ok := parsePrefix(block.CIDR)
		if !ok || block.Policy == "" {
			add("invalid ipBlock", block.Policy, block.CIDR)
			continue
		}
		var except []netip.Prefix
		for _, raw := range block.Except {
			x, valid := parsePrefix(raw)
			if !valid || !p.Contains(x.Addr()) || p.Bits() >= x.Bits() {
				add("invalid ipBlock exception", block.Policy, block.CIDR, raw)
				continue
			}
			except = append(except, x)
		}
		slices.SortFunc(except, func(a, b netip.Prefix) int { return a.Addr().Compare(b.Addr()) })
		if p.Bits() == 0 || len(cluster) == 0 {
			add("overly broad or unaudited ipBlock", block.Policy, block.CIDR)
			continue
		}
		for _, c := range cluster {
			if !p.Overlaps(c) {
				continue
			}
			intersection := c
			if p.Bits() > c.Bits() {
				intersection = p
			}
			if !covered(intersection, except) {
				add("ipBlock overlaps cluster CIDR", block.Policy, block.CIDR, c.String())
			}
		}
	}
}

// Workloads outside the reverse tool graph need no tool-specific traversal.
func ancestors(targets map[string]bool, predecessors map[string][]string) map[string]bool {
	seen := make(map[string]bool)
	var queue []string
	for target := range targets {
		seen[target] = true
		queue = append(queue, target)
	}
	for head := 0; head < len(queue); head++ {
		for _, previous := range predecessors[queue[head]] {
			if !seen[previous] {
				seen[previous] = true
				queue = append(queue, previous)
			}
		}
	}
	return seen
}
