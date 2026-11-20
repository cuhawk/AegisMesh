package prover_test

import (
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/cuhawk/AegisMesh/internal/compiler"
	"github.com/cuhawk/AegisMesh/internal/intent"
	"github.com/cuhawk/AegisMesh/internal/prover"
)

func wave3Fixture(t *testing.T) intent.Intent {
	t.Helper()
	f, err := os.Open("../../examples/wave3.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	in, err := intent.Decode(f)
	if err != nil {
		t.Fatal(err)
	}
	return in
}

func TestWave3HostileMutations(t *testing.T) {
	tests := []struct {
		name, property, witness string
		mutate                  func(*intent.Intent)
	}{
		{"missing authority", "invalid tool isolation", "catalog-tool -> lookup", func(in *intent.Intent) { in.JWTAuthority = nil }},
		{"plaintext JWKS", "invalid JWT-SVID authority", "https://identity.example.com -> http://identity.example.com/jwks.json", func(in *intent.Intent) {
			in.JWTAuthority.JWKSURI = "http://identity.example.com/jwks.json"
		}},
		{"missing agent identity", "agent-to-tool edge lacks scoped model identity", "agent -> catalog-tool", func(in *intent.Intent) {
			in.Workloads[0].Claims = nil
		}},
		{"wildcard model", "invalid model identity claims", "agent -> * -> spiffe://cluster.local/platform/delegator", func(in *intent.Intent) {
			in.Workloads[0].Claims.ModelID = "*"
		}},
		{"foreign delegator", "invalid model identity claims", "agent -> catalog-model:v2 -> spiffe://other.local/platform/delegator", func(in *intent.Intent) {
			in.Workloads[0].Claims.DelegatorSub = "spiffe://other.local/platform/delegator"
		}},
		{"self delegation", "invalid model identity claims", "agent -> catalog-model:v2 -> spiffe://cluster.local/ns/research/sa/agent", func(in *intent.Intent) {
			in.Workloads[0].Claims.DelegatorSub = in.Workloads[0].SPIFFEID(in.TrustDomain)
		}},
		{"duplicate scope", "invalid model tool scope", "agent -> lookup", func(in *intent.Intent) {
			in.Workloads[0].Claims.ToolScopes = []string{"lookup", "lookup"}
		}},
		{"wrong edge scope", "agent-to-tool edge lacks scoped model identity", "agent -> catalog-tool", func(in *intent.Intent) {
			in.Rules[7].ToolScope = "write"
		}},
		{"agent lacks tool scope", "agent-to-tool edge lacks scoped model identity", "agent -> catalog-tool", func(in *intent.Intent) {
			in.Workloads[0].Claims.ToolScopes = []string{"write"}
		}},
		{"proxy bypasses tool claims", "agent-to-tool edge lacks scoped model identity", "catalog -> catalog-tool", func(in *intent.Intent) {
			in.Rules = append(in.Rules, link("catalog", "catalog-tool", "proxy"))
		}},
		{"transitive tool deputy", "tool reachable through an unauthorized deputy", "catalog -> agent -> catalog-tool", func(in *intent.Intent) {
			in.Rules = append(in.Rules, link("catalog", "agent", "proxy"))
		}},
		{"deputy escalates a permitted tool to another operation", "tool reachable through an unauthorized deputy", "catalog -> agent -> catalog-tool", func(in *intent.Intent) {
			in.Workloads[1].Claims = in.Workloads[0].Claims
			r := in.Rules[7]
			r.From, r.Path = "catalog", "/preview"
			in.Rules = append(in.Rules, r, link("catalog", "agent", "proxy"))
			// Remove gateway access so catalog is the only unauthorized caller.
			in.HTTPRoutes, in.ReferenceGrants = nil, nil
			in.Rules = slices.Delete(in.Rules, 8, 9)
		}},
		{"tool explicitly forbidden", "neverReach violated", "agent -> catalog-tool", func(in *intent.Intent) {
			in.NeverReach = append(in.NeverReach, intent.Pair{From: "agent", To: "catalog-tool"})
		}},
		{"public tool", "invalid tool isolation", "catalog-tool -> lookup", func(in *intent.Intent) {
			in.Workloads[3].Ingress = true
		}},
		{"missing destination consent", "HTTPRoute lacks a matching ReferenceGrant", "edge/catalog -> research/catalog", func(in *intent.Intent) {
			in.ReferenceGrants = nil
		}},
		{"wrong grant source", "HTTPRoute lacks a matching ReferenceGrant", "edge/catalog -> research/catalog", func(in *intent.Intent) {
			in.ReferenceGrants[0].FromNamespace = "tools"
		}},
		{"wrong grant service", "HTTPRoute lacks a matching ReferenceGrant", "edge/catalog -> research/catalog", func(in *intent.Intent) {
			in.ReferenceGrants[0].Service = "other"
		}},
		{"wildcard service grant", "invalid or duplicate ReferenceGrant", "research/edge-to-catalog -> edge -> *", func(in *intent.Intent) {
			in.ReferenceGrants[0].Service = "*"
		}},
		{"method mismatch at gateway", "HTTPRoute lacks a verified gateway backend edge", "edge/catalog -> edge -> catalog", func(in *intent.Intent) {
			in.HTTPRoutes[0].Method = "POST"
		}},
		{"wildcard route hostname", "HTTPRoute lacks a verified gateway backend edge", "edge/catalog -> edge -> catalog", func(in *intent.Intent) {
			in.HTTPRoutes[0].Hostname = "*.example.com"
		}},
		{"duplicate route match", "conflicting HTTPRoute match", "edge/catalog -> edge/alternate", func(in *intent.Intent) {
			r := in.HTTPRoutes[0]
			r.Name = "alternate"
			in.HTTPRoutes = append(in.HTTPRoutes, r)
		}},
		{"loopback without isolation", "unisolated Envoy admin listener", "edge -> 127.0.0.1:15000", func(in *intent.Intent) {
			in.Isolation.EnvoyAdmins[0].Isolated = false
		}},
		{"IPv6 wildcard admin", "unisolated Envoy admin listener", "edge -> [::]:15000", func(in *intent.Intent) {
			in.Isolation.EnvoyAdmins[0].Address = "[::]:15000"
		}},
		{"cross-namespace TLS secret collision", "TLS secret sync name collision", "edge/catalog-tls -> edge-catalog/tls -> cilium-secrets/edge-catalog-tls", func(in *intent.Intent) {
			in.Isolation.TLSSecretSyncs = append(in.Isolation.TLSSecretSyncs, intent.TLSSecretSync{
				SourceNamespace: "edge-catalog", SourceName: "tls", TargetNamespace: "cilium-secrets", TargetName: "edge-catalog-tls",
			})
		}},
		{"cluster-wide ipBlock", "ipBlock overlaps cluster CIDR", "edge/partner-egress -> 10.0.0.0/8 -> 10.42.0.0/16", func(in *intent.Intent) {
			in.Isolation.IPBlocks[0].CIDR = "10.0.0.0/8"
		}},
		{"partially excluded IPv6 cluster", "ipBlock overlaps cluster CIDR", "edge/partner-egress -> fd42::/16 -> fd42:42::/64", func(in *intent.Intent) {
			in.Isolation.IPBlocks[0].CIDR = "fd42::/16"
			in.Isolation.IPBlocks[0].Except = []string{"fd42:42::/65"}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := wave3Fixture(t)
			tt.mutate(&in)
			findings := prover.Check(in)
			if !slices.ContainsFunc(findings, func(f prover.Finding) bool {
				return f.Property == tt.property && strings.Join(f.Witness, " -> ") == tt.witness
			}) {
				t.Fatalf("wanted %s with witness %s, got %v", tt.property, tt.witness, findings)
			}
			if _, err := compiler.Compile(in); err == nil {
				t.Fatal("compiler emitted policy for a rejected intent")
			}
		})
	}
}

func TestWave3CleanTopologies(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*intent.Intent)
	}{
		{"cross-namespace gateway and delegated tool", func(*intent.Intent) {}},
		{"route colocated with private backend", func(in *intent.Intent) {
			in.HTTPRoutes[0].Namespace = "research"
			in.ReferenceGrants = nil
		}},
		{"dedicated gateway and routing namespaces", func(in *intent.Intent) {
			in.HTTPRoutes[0].Namespace = "routes"
			in.ReferenceGrants[0].FromNamespace = "routes"
		}},
		{"two public hosts sharing scoped backend", func(in *intent.Intent) {
			r := in.HTTPRoutes[0]
			r.Name, r.Hostname = "mobile", "mobile.example.com"
			in.HTTPRoutes = append(in.HTTPRoutes, r)
		}},
		{"two isolated tools with separate scopes", func(in *intent.Intent) {
			in.Workloads[0].Claims.ToolScopes = append(in.Workloads[0].Claims.ToolScopes, "summarize")
			tool := in.Workloads[3]
			tool.ID, tool.ServiceAccount, tool.ToolScope = "summary-tool", "summary-tool", "summarize"
			in.Workloads = append(in.Workloads, tool)
			r := in.Rules[7]
			r.To, r.Path, r.ToolScope = tool.ID, "/summarize", tool.ToolScope
			in.Rules = append(in.Rules, r)
		}},
		{"dual-stack partner egress with split pod exclusions", func(in *intent.Intent) {
			in.Isolation.IPBlocks = []intent.IPBlock{
				{Policy: "edge/partner4", CIDR: "10.0.0.0/8", Except: []string{"10.42.128.0/17", "10.42.0.0/17"}},
				{Policy: "edge/partner6", CIDR: "fd42::/16", Except: []string{"fd42:42::/64"}},
			}
		}},
		{"IPv6 loopback and distinct tenant TLS projections", func(in *intent.Intent) {
			in.Isolation.EnvoyAdmins[0].Address = "[::1]:15000"
			in.Isolation.TLSSecretSyncs = append(in.Isolation.TLSSecretSyncs, intent.TLSSecretSync{
				SourceNamespace: "billing", SourceName: "catalog-tls", TargetNamespace: "cilium-secrets", TargetName: "billing-catalog-tls",
			})
		}},
		{"isolated admin socket and tool without public routes", func(in *intent.Intent) {
			in.Isolation.EnvoyAdmins[0].Address = "unix:/run/envoy/admin.sock"
			in.HTTPRoutes, in.ReferenceGrants = nil, nil
			in.Rules = slices.Delete(in.Rules, 8, 9)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := wave3Fixture(t)
			tt.configure(&in)
			bundle, err := compiler.Compile(in)
			if err != nil {
				t.Fatal(err)
			}
			if len(bundle.ToolAuthorizations) == 0 {
				t.Fatal("missing tool authorization")
			}
			for _, policy := range bundle.CiliumHTTP {
				if policy["kind"] != "CiliumNetworkPolicy" || policy["metadata"].(map[string]any)["namespace"] != "tools" {
					continue
				}
				spec := policy["spec"].(map[string]any)
				if len(spec["ingress"].([]map[string]any)) != 1 {
					t.Fatal("Cilium-only profile admitted claim-scoped traffic")
				}
			}
			slices.Reverse(in.HTTPRoutes)
			slices.Reverse(in.ReferenceGrants)
			slices.Reverse(in.Rules)
			slices.Reverse(in.Workloads)
			reordered, err := compiler.Compile(in)
			if err != nil || !reflect.DeepEqual(bundle, reordered) {
				t.Fatalf("reordering changed the bundle: %v", err)
			}
		})
	}
}
