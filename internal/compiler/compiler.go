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
	CiliumHTTP []object                    `json:"ciliumHTTP"`
	Kubernetes []object                    `json:"kubernetes"`
	SPIRE      []object                    `json:"spire"`
	Terraform  object                      `json:"terraform"`
	IAM        map[string]terraform.Policy `json:"iam"`
}

func manifest(api, kind, name, namespace string, spec object) object {
	metadata := object{"name": name}
	if namespace != "" {
		metadata["namespace"] = namespace
	}
	return object{"apiVersion": api, "kind": kind, "metadata": metadata, "spec": spec}
}

func endpoint(w intent.Workload, qualified bool) object {
	labels := object{"io.cilium.k8s.policy.serviceaccount": w.ServiceAccount}
	if qualified {
		labels["k8s:io.kubernetes.pod.namespace"] = w.Namespace
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

func principal(w intent.Workload, trustDomain string) string {
	return trustDomain + "/ns/" + w.Namespace + "/sa/" + w.ServiceAccount
}

// Compile is deterministic for logically identical input orderings.
func Compile(in intent.Intent) (Bundle, error) {
	if err := prover.RequireSafe(in); err != nil {
		return Bundle{}, err
	}
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
	b := Bundle{Terraform: tf, IAM: iam}
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
	workloads := make(map[string]intent.Workload)
	resources := make(map[string]intent.Resource)
	for _, w := range in.Workloads {
		workloads[w.ID] = w
	}
	for _, r := range in.Resources {
		resources[r.ID] = r
	}
	ingress := make(map[string][]object)
	httpIngress := make(map[string][]object)
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
			http := object{"http": []object{{"method": "^" + r.Method + "$", "path": "^" + regexp.QuoteMeta(r.Path) + "$"}}}
			httpIngress[r.To] = append(httpIngress[r.To], object{"fromEndpoints": []object{endpoint(from, true)}, "toPorts": port(r.Port, "TCP", http)})
			ingress[r.To] = append(ingress[r.To], object{"fromEndpoints": []object{endpoint(from, true)}, "toPorts": port(r.Port, "TCP", nil)})
			egress[r.From] = append(egress[r.From], object{"toEndpoints": []object{endpoint(to, true)}, "toPorts": port(r.Port, "TCP", nil)})
			authz[r.To] = append(authz[r.To], object{
				"from": []object{{"source": object{"principals": []string{principal(from, in.TrustDomain)}}}},
				"to":   []object{{"operation": object{"methods": []string{r.Method}, "paths": []string{r.Path}, "ports": []string{strconv.Itoa(r.Port)}}}},
			})
		case "dns":
			name := resources[r.To].Value
			dns[r.From] = append(dns[r.From], object{"matchName": name})
			egress[r.From] = append(egress[r.From], object{"toFQDNs": []object{{"matchName": name}}, "toPorts": port(r.Port, "TCP", nil)})
		case "assume":
			roles[r.From] = resources[r.To].Value
		}
	}
	namespaces := make(map[string]bool)
	for _, w := range in.Workloads {
		selector := object{"matchLabels": object{"aegismesh.io/workload": w.ID}}
		if len(dns[w.ID]) != 0 {
			egress[w.ID] = append(egress[w.ID], object{
				"toEndpoints": []object{{"matchLabels": object{"k8s:io.kubernetes.pod.namespace": "kube-system", "k8s:k8s-app": "kube-dns"}}},
				"toPorts":     port(53, "ANY", object{"dns": dns[w.ID]}),
			})
		}
		spec := object{"endpointSelector": endpoint(w, false), "enableDefaultDeny": object{"ingress": true, "egress": true}}
		spec["ingress"] = append([]object{{"fromEntities": []string{"none"}}}, ingress[w.ID]...)
		spec["egress"] = append([]object{{"toEntities": []string{"none"}}}, egress[w.ID]...)
		b.Kubernetes = append(b.Kubernetes, manifest(cilium, "CiliumNetworkPolicy", w.ID, w.Namespace, spec))
		httpSpec := maps.Clone(spec)
		httpSpec["ingress"] = append([]object{{"fromEntities": []string{"none"}}}, httpIngress[w.ID]...)
		b.CiliumHTTP = append(b.CiliumHTTP, manifest(cilium, "CiliumNetworkPolicy", w.ID, w.Namespace, httpSpec))
		auth := object{"selector": selector, "action": "ALLOW"}
		if len(authz[w.ID]) > 0 {
			auth["rules"] = authz[w.ID]
		}
		b.Kubernetes = append(b.Kubernetes, manifest(istio, "AuthorizationPolicy", w.ID, w.Namespace, auth))
		if !namespaces[w.Namespace] {
			namespaces[w.Namespace] = true
			b.Kubernetes = append(b.Kubernetes, manifest(istio, "PeerAuthentication", "aegismesh-strict", w.Namespace, object{"mtls": object{"mode": "STRICT"}}))
		}
		b.SPIRE = append(b.SPIRE, object{
			"spiffe_id":     "spiffe://" + principal(w, in.TrustDomain),
			"parent_id":     in.SPIREParent,
			"x509_svid_ttl": w.SVIDTTL,
			"selectors": []object{
				{"type": "k8s", "value": "ns:" + w.Namespace},
				{"type": "k8s", "value": "sa:" + w.ServiceAccount},
			},
		})
		if role := roles[w.ID]; role != "" {
			sa := object{
				"apiVersion": "v1", "kind": "ServiceAccount", "metadata": object{
					"name": w.ServiceAccount, "namespace": w.Namespace, "annotations": object{"eks.amazonaws.com/role-arn": role},
				},
			}
			b.Kubernetes = append(b.Kubernetes, sa)
			b.CiliumHTTP = append(b.CiliumHTTP, sa)
		}
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
