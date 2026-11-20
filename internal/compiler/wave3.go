package compiler

import (
	"cmp"
	"slices"
	"strconv"

	"github.com/cuhawk/AegisMesh/internal/intent"
)

// ToolAuthorization is the shared contract for the Istio and OPA policies.
type ToolAuthorization struct {
	Namespace    string `json:"namespace"`
	Tool         string `json:"tool"`
	Principal    string `json:"principal"`
	Subject      string `json:"subject"`
	Audience     string `json:"audience"`
	Issuer       string `json:"issuer"`
	JWKSURI      string `json:"jwksURI"`
	ModelID      string `json:"model_id"`
	ToolScope    string `json:"tool_scope"`
	DelegatorSub string `json:"delegator_sub"`
	Method       string `json:"method"`
	Path         string `json:"path"`
	Port         string `json:"port"`
}

func toolAuthorization(in intent.Intent, from, to intent.Workload, r intent.Rule) ToolAuthorization {
	return ToolAuthorization{
		Namespace: to.Namespace, Tool: to.ID, Principal: from.Principal(in.TrustDomain),
		Subject: from.SPIFFEID(in.TrustDomain), Audience: to.SPIFFEID(in.TrustDomain),
		Issuer: in.JWTAuthority.Issuer, JWKSURI: in.JWTAuthority.JWKSURI,
		ModelID: from.Claims.ModelID, ToolScope: r.ToolScope, DelegatorSub: from.Claims.DelegatorSub,
		Method: r.Method, Path: r.Path, Port: strconv.Itoa(r.Port),
	}
}

func (a ToolAuthorization) constrain(rule object) {
	rule["when"] = []object{
		{"key": "request.auth.claims[iss]", "values": []string{a.Issuer}},
		{"key": "request.auth.claims[sub]", "values": []string{a.Subject}},
		{"key": "request.auth.claims[aud]", "values": []string{a.Audience}},
		{"key": "request.auth.claims[model_id]", "values": []string{a.ModelID}},
		{"key": "request.auth.claims[tool_scopes]", "values": []string{a.ToolScope}},
		{"key": "request.auth.claims[delegator_sub]", "values": []string{a.DelegatorSub}},
	}
}

func gatewayArtifacts(in intent.Intent, workloads map[string]intent.Workload) []object {
	routes := slices.Clone(in.HTTPRoutes)
	slices.SortFunc(routes, func(a, b intent.HTTPRoute) int {
		return cmp.Or(cmp.Compare(a.Namespace, b.Namespace), cmp.Compare(a.Name, b.Name))
	})
	grants := slices.Clone(in.ReferenceGrants)
	slices.SortFunc(grants, func(a, b intent.ReferenceGrant) int {
		return cmp.Or(cmp.Compare(a.Namespace, b.Namespace), cmp.Compare(a.Name, b.Name))
	})
	const group = "gateway.networking.k8s.io"
	var result []object
	for _, g := range grants {
		result = append(result, manifest(group+"/v1beta1", "ReferenceGrant", g.Name, g.Namespace, object{
			"from": []object{{"group": group, "kind": "HTTPRoute", "namespace": g.FromNamespace}},
			"to":   []object{{"group": "", "kind": "Service", "name": g.Service}},
		}))
	}
	for _, r := range routes {
		parent := object{"name": workloads[r.Gateway].ID, "sectionName": r.Listener}
		backend := object{"name": r.Service, "port": r.Port}
		if ns := workloads[r.Gateway].Namespace; ns != r.Namespace {
			parent["namespace"] = ns
		}
		if ns := workloads[r.Backend].Namespace; ns != r.Namespace {
			backend["namespace"] = ns
		}
		result = append(result, manifest(group+"/v1", "HTTPRoute", r.Name, r.Namespace, object{
			"parentRefs": []object{parent}, "hostnames": []string{r.Hostname},
			"rules": []object{{
				"matches":     []object{{"method": r.Method, "path": object{"type": "Exact", "value": r.Path}}},
				"backendRefs": []object{backend},
			}},
		}))
	}
	return result
}
