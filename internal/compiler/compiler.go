// Package compiler translates a verified intent to portable policy artifacts.
package compiler

import (
	"cmp"
	_ "embed"
	"encoding/json"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/cuhawk/AegisMesh/internal/intent"
	"github.com/cuhawk/AegisMesh/internal/prover"
	"github.com/cuhawk/AegisMesh/internal/terraform"
)

type object = map[string]any

type Bundle struct {
	Wave6              bool                         `json:"wave6,omitempty"`
	MCPAuthorizations  []MCPAuthorization           `json:"mcpAuthorizations,omitempty"`
	Clusters           map[string]*ClusterArtifacts `json:"clusters,omitempty"`
	Tetragon           []object                     `json:"tetragon,omitempty"`
	CiliumHTTP         []object                     `json:"ciliumHTTP"`
	Kubernetes         []object                     `json:"kubernetes"`
	SPIRE              []object                     `json:"spire"`
	Terraform          object                       `json:"terraform"`
	IAM                map[string]terraform.Policy  `json:"iam"`
	ToolAuthorizations []ToolAuthorization          `json:"toolAuthorizations,omitempty"`
}

func manifest(api, kind, name, namespace string, spec object) object {
	metadata := object{"name": name}
	if namespace != "" {
		metadata["namespace"] = namespace
	}
	return object{"apiVersion": api, "kind": kind, "metadata": metadata, "spec": spec}
}

func endpoint(w intent.Workload, qualified bool, cluster string) object {
	labels := object{"io.cilium.k8s.policy.serviceaccount": w.ServiceAccount}
	if qualified {
		labels["k8s:io.kubernetes.pod.namespace"] = w.Namespace
	}
	if cluster != "" {
		labels["io.cilium.k8s.policy.cluster"] = cluster
	}
	return object{"matchLabels": labels}
}

func port(p int, protocol string, rules object) []object {
	result := object{"ports": []object{{"port": strconv.Itoa(p), "protocol": protocol}}}
	if rules != nil {
		result["rules"] = rules
	}
	return []object{result}
}

// Compile is deterministic for logically identical input orderings.
func Compile(in intent.Intent) (Bundle, error) {
	if err := prover.RequireSafe(in); err != nil {
		return Bundle{}, err
	}
	in = in.WithMCPRules()
	in.Workloads = slices.Clone(in.Workloads)
	in.Rules = slices.Clone(in.Rules)
	slices.SortFunc(in.Workloads, func(a, b intent.Workload) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(in.Rules, func(a, b intent.Rule) int {
		return cmp.Or(cmp.Compare(a.From, b.From), cmp.Compare(a.To, b.To),
			cmp.Compare(a.Kind, b.Kind), cmp.Compare(a.Port, b.Port),
			cmp.Compare(a.Method, b.Method), cmp.Compare(a.Path, b.Path))
	})
	tf, iam, err := terraform.Render(in)
	if err != nil {
		return Bundle{}, err
	}
	b := Bundle{Terraform: tf, IAM: iam, Clusters: federationBindings(in), Wave6: in.GCP != nil || len(in.MCP) != 0}
	addKubernetes := func(cluster string, o object) {
		b.Kubernetes = append(b.Kubernetes, o)
		if target := b.Clusters[cluster]; target != nil {
			target.Kubernetes = append(target.Kubernetes, o)
		}
	}
	addCiliumHTTP := func(cluster string, o object) {
		b.CiliumHTTP = append(b.CiliumHTTP, o)
		if target := b.Clusters[cluster]; target != nil {
			target.CiliumHTTP = append(target.CiliumHTTP, o)
		}
	}
	cilium := "cilium.io/v2"
	istio := "security.istio.io/v1"
	// Scope the baseline to labeled workloads. An explicit none peer enables
	// isolation in directions with no workload-specific allow rules.
	b.Kubernetes = append(b.Kubernetes, manifest(cilium, "CiliumClusterwideNetworkPolicy", "aegismesh-isolation", "", object{
		"endpointSelector":  object{"matchExpressions": []object{{"key": "k8s:aegismesh.io/workload", "operator": "Exists"}}},
		"enableDefaultDeny": object{"ingress": true, "egress": true},
		"ingress":           []object{{"fromEntities": []string{"none"}}},
		"egress":            []object{{"toEntities": []string{"none"}}},
		"egressDeny":        []object{{"toCIDR": []string{"169.254.169.254/32", "fd00:ec2::254/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}}},
	}))

	b.CiliumHTTP = append(b.CiliumHTTP, b.Kubernetes[0])
	for _, cluster := range b.Clusters {
		cluster.Kubernetes = append(cluster.Kubernetes, b.Kubernetes[0])
		cluster.CiliumHTTP = append(cluster.CiliumHTTP, b.Kubernetes[0])
	}
	workloads := make(map[string]intent.Workload)
	resources := make(map[string]intent.Resource)
	for _, w := range in.Workloads {
		workloads[w.ID] = w
	}
	for _, r := range in.Resources {
		resources[r.ID] = r
	}
	b.MCPAuthorizations = mcpAuthorizations(in, workloads, resources)
	mcpAgents, mcpGateways := make(map[string]bool), make(map[string]bool)
	for _, m := range in.MCP {
		mcpAgents[m.Agent], mcpGateways[m.Gateway] = true, true
	}
	ingress := make(map[string][]object)
	httpIngress := make(map[string][]object)
	httpEgress := make(map[string][]object)
	egress := make(map[string][]object)
	authz := make(map[string][]object)
	dns := make(map[string][]object)
	roles := make(map[string]string)
	for _, r := range in.Rules {
		if r.Deny {
			continue
		}
		switch r.Kind {
		case "http":
			from, to := workloads[r.From], workloads[r.To]
			fromCluster, toCluster := in.Cluster(from), in.Cluster(to)
			fromEndpoints := []object{endpoint(from, true, fromCluster)}
			toEntry := object{"toEndpoints": []object{endpoint(to, true, toCluster)}, "toPorts": port(r.Port, "TCP", nil)}
			ingress[r.To] = append(ingress[r.To], object{"fromEndpoints": fromEndpoints, "toPorts": port(r.Port, "TCP", nil)})
			egress[r.From] = append(egress[r.From], toEntry)
			if fromCluster == toCluster && to.ToolScope == "" && !mcpGateways[r.To] {
				http := object{"http": []object{{"method": "^" + r.Method + "$", "path": "^" + regexp.QuoteMeta(r.Path) + "$"}}}
				httpIngress[r.To] = append(httpIngress[r.To], object{"fromEndpoints": fromEndpoints, "toPorts": port(r.Port, "TCP", http)})
				if in.Federation != nil {
					httpEgress[r.From] = append(httpEgress[r.From], toEntry)
				}
			}
			rule := object{
				"from": []object{{"source": object{"principals": []string{from.Principal(in.TrustDomain)}}}},
				"to":   []object{{"operation": object{"methods": []string{r.Method}, "paths": []string{r.Path}, "ports": []string{strconv.Itoa(r.Port)}}}},
			}
			if to.ToolScope != "" {
				a := toolAuthorization(in, from, to, r)
				a.constrain(rule)
				b.ToolAuthorizations = append(b.ToolAuthorizations, a)
			}
			authz[r.To] = append(authz[r.To], rule)
		case "dns":
			name := resources[r.To].Value
			dns[r.From] = append(dns[r.From], object{"matchName": name})
			entry := object{"toFQDNs": []object{{"matchName": name}}, "toPorts": port(r.Port, "TCP", nil)}
			egress[r.From] = append(egress[r.From], entry)
			httpEgress[r.From] = append(httpEgress[r.From], entry)
		case "assume":
			roles[r.From] = resources[r.To].Value
		}
	}
	namespaces := make(map[[2]string]bool)
	for _, w := range in.Workloads {
		cluster := in.Cluster(w)
		selector := object{"matchLabels": object{"aegismesh.io/workload": w.ID}}
		if len(dns[w.ID]) != 0 {
			dnsSelector := object{"k8s:io.kubernetes.pod.namespace": "kube-system", "k8s:k8s-app": "kube-dns"}
			if cluster != "" {
				dnsSelector["io.cilium.k8s.policy.cluster"] = cluster
			}
			dnsAccess := object{
				"toEndpoints": []object{{"matchLabels": dnsSelector}},
				"toPorts":     port(53, "ANY", object{"dns": dns[w.ID]}),
			}
			egress[w.ID] = append(egress[w.ID], dnsAccess)
			httpEgress[w.ID] = append(httpEgress[w.ID], dnsAccess)
		}
		spec := object{"endpointSelector": endpoint(w, false, ""), "enableDefaultDeny": object{"ingress": true, "egress": true}}
		spec["ingress"] = append([]object{{"fromEntities": []string{"none"}}}, ingress[w.ID]...)
		spec["egress"] = append([]object{{"toEntities": []string{"none"}}}, egress[w.ID]...)
		addKubernetes(cluster, manifest(cilium, "CiliumNetworkPolicy", w.ID, w.Namespace, spec))
		httpSpec := maps.Clone(spec)
		httpSpec["ingress"] = append([]object{{"fromEntities": []string{"none"}}}, httpIngress[w.ID]...)
		if in.Federation != nil || mcpAgents[w.ID] {
			httpSpec["egress"] = append([]object{{"toEntities": []string{"none"}}}, httpEgress[w.ID]...)
		}
		addCiliumHTTP(cluster, manifest(cilium, "CiliumNetworkPolicy", w.ID, w.Namespace, httpSpec))
		auth := object{"selector": selector, "action": "ALLOW"}
		if len(authz[w.ID]) > 0 {
			auth["rules"] = authz[w.ID]
		}
		addKubernetes(cluster, manifest(istio, "AuthorizationPolicy", w.ID, w.Namespace, auth))
		if w.ToolScope != "" {
			addKubernetes(cluster, manifest(istio, "RequestAuthentication", w.ID, w.Namespace, object{
				"selector": selector,
				"jwtRules": []object{{
					"issuer": in.JWTAuthority.Issuer, "jwksUri": in.JWTAuthority.JWKSURI,
					"audiences": []string{w.SPIFFEID(in.TrustDomain)},
				}},
			}))
		}
		ns := [2]string{cluster, w.Namespace}
		if !namespaces[ns] {
			namespaces[ns] = true
			addKubernetes(cluster, manifest(istio, "PeerAuthentication", "aegismesh-strict", w.Namespace, object{"mtls": object{"mode": "STRICT"}}))
		}
		entry := object{
			"spiffe_id":     w.SPIFFEID(in.TrustDomain),
			"parent_id":     in.SPIREParent,
			"x509_svid_ttl": w.SVIDTTL,
			"selectors": []object{
				{"type": "k8s", "value": "ns:" + w.Namespace},
				{"type": "k8s", "value": "sa:" + w.ServiceAccount},
			},
		}
		if target := b.Clusters[cluster]; target != nil {
			domain := in.Federation.TrustDomains[target.TrustDomain]
			entry["parent_id"] = domain.SPIREParent
			if len(domain.Trusts) != 0 {
				peers := slices.Clone(domain.Trusts)
				slices.Sort(peers)
				entry["federates_with"] = peers
			}
			target.SPIRE = append(target.SPIRE, entry)
		}
		b.SPIRE = append(b.SPIRE, entry)
		if w.Admission != nil {
			b.Wave6 = true
			policy := admissionPolicy(w)
			addKubernetes(cluster, policy)
			addCiliumHTTP(cluster, policy)
		}
		if len(w.ExecAllowlist) != 0 {
			policy := executionPolicy(w)
			if mcpAgents[w.ID] {
				policy["spec"].(object)["kprobes"] = mcpSocketGuard()
			}
			b.Tetragon = append(b.Tetragon, policy)
			if target := b.Clusters[cluster]; target != nil {
				target.Tetragon = append(target.Tetragon, policy)
			}
		}
		if role := roles[w.ID]; role != "" {
			sa := object{
				"apiVersion": "v1", "kind": "ServiceAccount", "metadata": object{
					"name": w.ServiceAccount, "namespace": w.Namespace, "annotations": object{"eks.amazonaws.com/role-arn": role},
				},
			}
			addKubernetes(cluster, sa)
			addCiliumHTTP(cluster, sa)
		}
	}
	gateway := gatewayArtifacts(in, workloads)
	b.Kubernetes = append(b.Kubernetes, gateway...)
	b.CiliumHTTP = append(b.CiliumHTTP, gateway...)
	for cluster, target := range b.Clusters {
		local := in
		local.HTTPRoutes, local.ReferenceGrants = nil, nil
		for _, route := range in.HTTPRoutes {
			if in.Cluster(workloads[route.Gateway]) != cluster {
				continue
			}
			local.HTTPRoutes = append(local.HTTPRoutes, route)
		}
		for _, grant := range in.ReferenceGrants {
			if slices.ContainsFunc(local.HTTPRoutes, func(route intent.HTTPRoute) bool {
				return route.Namespace == grant.FromNamespace && route.Service == grant.Service &&
					workloads[route.Backend].Namespace == grant.Namespace
			}) {
				local.ReferenceGrants = append(local.ReferenceGrants, grant)
			}
		}
		artifacts := gatewayArtifacts(local, workloads)
		target.Kubernetes = append(target.Kubernetes, artifacts...)
		target.CiliumHTTP = append(target.CiliumHTTP, artifacts...)
	}
	return b, nil
}

func JSON(v any) ([]byte, error) {
	result, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(result, '\n'), nil
}

// Gate validates baseline policy invariants in emitted bundles.
//
//go:embed gate.rego
var Gate string
