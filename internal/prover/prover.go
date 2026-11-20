// Package prover checks the declared capability graph before policy emission.
package prover

import (
	"fmt"
	"maps"
	"net/netip"
	"regexp"
	"slices"
	"strings"

	"github.com/cuhawk/AegisMesh/internal/intent"
)

type Finding struct {
	Property string   `json:"property"`
	Witness  []string `json:"witness"`
}

func (f Finding) String() string { return f.Property + ": " + strings.Join(f.Witness, " -> ") }

var (
	label     = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	path      = regexp.MustCompile(`^(/[A-Za-z0-9._~-]+)*/?$`)
	provider  = regexp.MustCompile(`^arn:aws:iam::[0-9]{12}:oidc-provider/[a-z0-9.-]+(/[A-Za-z0-9._/-]+)?$`)
	role      = regexp.MustCompile(`^arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+$`)
	secret    = regexp.MustCompile(`^arn:aws:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]+$`)
	objectARN = regexp.MustCompile(`^arn:aws:s3:::[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]/[A-Za-z0-9._/-]+$`)
	methods   = []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
)

func domain(s string) bool {
	if len(s) > 253 || !strings.Contains(s, ".") {
		return false
	}
	for _, part := range strings.Split(s, ".") {
		if !label.MatchString(part) {
			return false
		}
	}
	_, err := netip.ParseAddr(s)
	return err != nil && s != "localhost.localdomain"
}

func validateRule(r intent.Rule, from, to string, source intent.Workload, resources map[string]intent.Resource) string {
	if r.Kind != "http" && (r.Method != "" || r.Path != "") ||
		r.Kind != "http" && r.Kind != "dns" && r.Port != 0 ||
		r.Kind != "assume" && (r.OIDCProvider != "" || r.Audience != "" || r.Subject != "") ||
		r.Kind != "read" && r.Kind != "assume" && r.Kind != "pass" && r.Action != "" ||
		r.ApprovedEgress && (r.Kind != "dns" || r.Deny) {
		return "unexpected rule fields"
	}
	switch r.Kind {
	case "http":
		if from == "workload" && to == "workload" && r.Port > 0 && r.Port <= 65535 &&
			slices.Contains(methods, r.Method) && strings.HasPrefix(r.Path, "/") && path.MatchString(r.Path) {
			for _, segment := range strings.Split(r.Path, "/") {
				if segment == "." || segment == ".." {
					return "noncanonical HTTP path"
				}
			}
			return ""
		}
	case "dns":
		if from == "workload" && to == "fqdn" && r.Port > 0 && r.Port <= 65535 && (!r.ApprovedEgress || !source.Untrusted) {
			return ""
		}
	case "read":
		if from == "role" && ((to == "vault" && r.Action == "secretsmanager:GetSecretValue") ||
			(to == "object" && r.Action == "s3:GetObject")) {
			return ""
		}
	case "assume":
		if from == "workload" && to == "role" && r.Action == "sts:AssumeRoleWithWebIdentity" &&
			provider.MatchString(r.OIDCProvider) && role.MatchString(resources[r.To].Value) && strings.Split(r.OIDCProvider, ":")[4] == strings.Split(resources[r.To].Value, ":")[4] &&
			r.Audience == "sts.amazonaws.com" && r.Subject == "system:serviceaccount:"+source.Namespace+":"+source.ServiceAccount {
			return ""
		}
	case "pass":
		// A pass-role grant alone cannot constrain which deputy receives credentials.
		return "PassRole prohibited"
	case "proxy", "redirect":
		if from == "workload" || from == "fqdn" {
			return ""
		}
	}
	return "invalid or overly broad " + r.Kind + " rule"
}

// Check audits rules, then proves invariants over a default-deny capability graph.
func Check(in intent.Intent) []Finding {
	var findings []Finding
	add := func(property string, witness ...string) {
		findings = append(findings, Finding{property, witness})
	}
	if !domain(in.TrustDomain) || len(in.Workloads) == 0 {
		add("invalid trust domain or empty workloads", in.TrustDomain)
	}
	if !validParent(in.TrustDomain, in.SPIREParent) {
		add("invalid SPIRE parent identity", in.SPIREParent)
	}
	kinds := make(map[string]string)
	workloads := make(map[string]intent.Workload)
	resources := make(map[string]intent.Resource)
	identities := make(map[string]string)
	targets := make(map[string]string)
	for _, w := range in.Workloads {
		if !label.MatchString(w.ID) || !label.MatchString(w.Namespace) || !label.MatchString(w.Tenant) ||
			!label.MatchString(w.ServiceAccount) || w.SVIDTTL < 1 || w.SVIDTTL > 3600 || kinds[w.ID] != "" {
			add("invalid or duplicate workload", w.ID)
		}
		checkWorkloadPolicy(in, w, add)
		identity := w.Principal(in.TrustDomain)
		if old, exists := identities[identity]; exists {
			add("shared workload identity", old, w.ID)
		}
		identities[identity] = w.ID
		kinds[w.ID], workloads[w.ID] = "workload", w
	}
	federatedReach := checkFederation(in, workloads, add)
	tools := checkIdentity(in, add)
	checkIsolation(in.Isolation, workloads, add)
	for _, resource := range in.Resources {
		valid := false
		switch resource.Kind {
		case "fqdn":
			valid = domain(resource.Value)
		case "vault":
			valid = secret.MatchString(resource.Value)
		case "object":
			valid = objectARN.MatchString(resource.Value)
		case "role":
			valid = role.MatchString(resource.Value)
		case "metadata":
			valid = resource.Value == "169.254.169.254" || resource.Value == "fd00:ec2::254"
		case "internet":
			valid = resource.Value == "world"
		case "cidr":
			prefix, err := netip.ParsePrefix(resource.Value)
			valid = err == nil && prefix.Bits() > 0 && prefix == prefix.Masked() && !prefix.Addr().Is4In6()
		}
		if !valid || !label.MatchString(resource.ID) || kinds[resource.ID] != "" {
			add("invalid, wildcard or duplicate resource", resource.ID, resource.Value)
		}
		key := resource.Kind + "/" + resource.Value
		if old, exists := targets[key]; exists {
			add("duplicate resource target", old, resource.ID)
		}
		targets[key] = resource.ID
		kinds[resource.ID], resources[resource.ID] = resource.Kind, resource
	}
	type match struct {
		intent.Pair
		kind, method, path string
		port               int
	}
	type ruleState struct{ allow, deny bool }
	states := make(map[match]ruleState)
	key := func(r intent.Rule) match { return match{r.Pair, r.Kind, r.Method, r.Path, r.Port} }
	for _, r := range in.Rules {
		from, to := kinds[r.From], kinds[r.To]
		if from == "" || to == "" {
			add("unknown rule endpoint", r.From, r.To)
			continue
		}
		if msg := validateRule(r, from, to, workloads[r.From], resources); msg != "" {
			add(msg, r.From, r.To)
			continue
		}
		fromWorkload, toWorkload := workloads[r.From], workloads[r.To]
		if !r.Deny && tools[r.To] {
			if r.Kind != "http" || fromWorkload.Claims == nil || r.ToolScope != toWorkload.ToolScope ||
				!slices.Contains(fromWorkload.Claims.ToolScopes, r.ToolScope) {
				add("agent-to-tool edge lacks scoped model identity", r.From, r.To)
				continue
			}
		} else if r.ToolScope != "" {
			add("unexpected tool scope on edge", r.From, r.To)
			continue
		}
		if in.Federation != nil && !r.Deny && to == "workload" {
			sourceDomain, targetDomain := fromWorkload.Domain(in.TrustDomain), toWorkload.Domain(in.TrustDomain)
			domains := in.Federation.TrustDomains
			if fromWorkload.ID == "" {
				add("federated workload edge lacks a workload identity", r.From, r.To)
			} else if sourceDomain != targetDomain && (r.Kind != "http" ||
				!slices.Contains(domains[sourceDomain].Trusts, targetDomain) ||
				!slices.Contains(domains[targetDomain].Trusts, sourceDomain)) {
				add("cross-domain edge requires HTTP and mutual bundle trust", r.From, sourceDomain, targetDomain, r.To)
			}
		}
		if !r.Deny && r.Kind == "http" && workloads[r.From].Tenant != workloads[r.To].Tenant {
			add("cross-tenant HTTP allow", r.From, r.To)
		}
		k := key(r)
		st := states[k]
		if (r.Deny && st.deny) || (!r.Deny && st.allow) {
			add("duplicate rule", r.From, r.To)
		}
		st.allow = st.allow || !r.Deny
		st.deny = st.deny || r.Deny
		states[k] = st
	}
	account := ""
	assumedRoles := make(map[string]string)
	trustedRoles := make(map[string]bool)
	for _, r := range in.Rules {
		if r.Kind != "assume" || r.Deny || !states[key(r)].allow || states[key(r)].deny {
			continue
		}
		if other := assumedRoles[r.From]; other != "" && other != r.To {
			add("multiple role bindings for one workload", r.From, other, r.To)
		}
		roleAccount := strings.Split(resources[r.To].Value, ":")[4]
		if account != "" && roleAccount != account {
			add("Terraform bundle spans multiple AWS accounts", r.From, r.To)
		}
		account = roleAccount
		assumedRoles[r.From], trustedRoles[r.To] = r.To, true
	}
	graph := make(map[string][]string)
	toolCalls := make(map[string][]intent.Rule)
	allowedToolCalls := make(map[match]bool)
	predecessors := make(map[string][]string)
	reachabilityTargets := maps.Clone(tools)
	gatewayEdges := make(map[gatewayMatch]bool)
	for _, r := range in.Rules {
		st := states[key(r)]
		if r.Deny || !st.allow {
			continue
		}
		if st.deny {
			add("allow shadowed by deny", r.From, r.To)
			continue
		}
		if r.Kind == "read" && !trustedRoles[r.From] {
			add("role grants access without managed trust", r.From, r.To)
		}
		graph[r.From] = append(graph[r.From], r.To)
		if in.Federation != nil {
			from, to := workloads[r.From], workloads[r.To]
			if to.ID != "" && (from.ID == "" || from.Domain(in.TrustDomain) != to.Domain(in.TrustDomain)) {
				reachabilityTargets[r.From] = true
			}
		}
		if len(tools) != 0 || in.Federation != nil {
			predecessors[r.To] = append(predecessors[r.To], r.From)
		}
		if r.Kind == "http" {
			if len(in.HTTPRoutes) != 0 {
				gatewayEdges[gatewayMatch{r.From, r.To, r.Method, r.Path, r.Port}] = true
			}
			if tools[r.To] {
				toolCalls[r.From] = append(toolCalls[r.From], r)
				allowedToolCalls[key(r)] = true
			}
		}
	}
	checkGateway(in, workloads, gatewayEdges, add)
	requiresTraversal := ancestors(reachabilityTargets, predecessors)
	for from := range graph {
		slices.Sort(graph[from])
	}
	// Index explicit queries by source so multiple properties share a traversal.
	queries := make(map[string][]string)
	for _, q := range in.NeverReach {
		if kinds[q.From] == "" || kinds[q.To] == "" {
			add("unknown neverReach endpoint", q.From, q.To)
			continue
		}
		queries[q.From] = append(queries[q.From], q.To)
	}
	sources := make([]string, 0, len(kinds))
	for id := range kinds {
		sources = append(sources, id)
	}
	slices.Sort(sources)
	for _, id := range sources {
		w := workloads[id]
		if !w.Ingress && !w.Untrusted && len(queries[id]) == 0 && (!requiresTraversal[id] || w.ID == "") {
			continue
		}
		previous := map[string]string{id: ""}
		queue := []string{id}
		witness := func(end string) []string {
			var nodes []string
			for at := end; at != ""; at = previous[at] {
				nodes = append(nodes, at)
			}
			slices.Reverse(nodes)
			return nodes
		}
		var vault, egress, egressVia string
		for head := 0; head < len(queue); head++ {
			current := queue[head]
			kind := kinds[current]
			if current != id && w.ID != "" {
				target := workloads[current]
				if in.Federation != nil && target.ID != "" && w.Domain(in.TrustDomain) != target.Domain(in.TrustDomain) &&
					!federatedReach[intent.Pair{From: id, To: current}] {
					add("unauthorized cross-domain reachability", witness(current)...)
				}
				for _, call := range toolCalls[current] {
					tool := call.To
					call.From = id
					if !allowedToolCalls[key(call)] {
						add("tool reachable through an unauthorized deputy", append(witness(current), tool)...)
					}
				}
			}
			if vault == "" && (kind == "vault" || kind == "object") {
				vault = current
			}
			if (w.Ingress || w.Untrusted) && (kind == "metadata" || containsMetadata(resources[current])) {
				add("metadata reachable", witness(current)...)
			}
			for _, next := range graph[current] {
				kind := kinds[next]
				if egress == "" && (kind == "internet" || kind == "cidr" || kind == "fqdn") {
					egress, egressVia = next, current
				}
				if _, seen := previous[next]; !seen {
					previous[next] = current
					queue = append(queue, next)
				}
			}
		}
		if w.Untrusted && vault != "" && egress != "" {
			add("Lethal Trifecta secret reachable", witness(vault)...)
			add("Lethal Trifecta unauthorized egress", append(witness(egressVia), egress)...)
		}
		for _, target := range queries[id] {
			if _, ok := previous[target]; ok {
				add("neverReach violated", witness(target)...)
			}
		}
	}
	return findings
}

func containsMetadata(r intent.Resource) bool {
	if r.Kind != "cidr" {
		return false
	}
	prefix, err := netip.ParsePrefix(r.Value)
	return err == nil && (prefix.Contains(netip.MustParseAddr("169.254.169.254")) || prefix.Contains(netip.MustParseAddr("fd00:ec2::254")))
}

func RequireSafe(in intent.Intent) error {
	findings := Check(in)
	if len(findings) != 0 {
		return fmt.Errorf("policy rejected: %v", findings)
	}
	return nil
}
