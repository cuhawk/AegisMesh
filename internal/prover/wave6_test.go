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

func wave6Fixture(t *testing.T) intent.Intent {
	t.Helper()
	f, err := os.Open("../../examples/wave6.json")
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

func editPerimeter(in *intent.Intent, edit func(*intent.GCPPerimeter)) {
	p := in.GCP.Perimeters["billing_perimeter"]
	edit(&p)
	in.GCP.Perimeters["billing_perimeter"] = p
}

func TestWave6HostileMutations(t *testing.T) {
	const (
		iam       = "GCP IAM binding"
		perimeter = "GCP service perimeter"
		project   = "GCP project"
		prefix    = "image registry prefix"
		mcp       = "invalid MCP agent"
		grant     = "MCP path grant"
	)
	tests := []struct {
		name, property string
		mutate         func(*intent.Intent)
	}{
		{"gcp-owner", iam, func(in *intent.Intent) { in.GCP.Bindings[0].Role = "roles/owner" }},
		{"gcp-wildcard-role", iam, func(in *intent.Intent) { in.GCP.Bindings[0].Role = "roles/*" }},
		{"gcp-unknown-member", iam, func(in *intent.Intent) { in.GCP.Bindings[0].Workload = "unknown" }},
		{"gcp-untrusted-member", iam, func(in *intent.Intent) { in.GCP.Bindings[0].Workload = "agent" }},
		{"gcp-ingress-member", iam, func(in *intent.Intent) { in.Workloads[2].Ingress = true }},
		{"gcp-repeat-binding", iam, func(in *intent.Intent) { in.GCP.Bindings = append(in.GCP.Bindings, in.GCP.Bindings[0]) }},
		{"gcp-missing-perimeter", "requires projects", func(in *intent.Intent) { in.GCP.Perimeters = nil }},
		{"gcp-unrestricted-role-service", iam, func(in *intent.Intent) {
			editPerimeter(in, func(p *intent.GCPPerimeter) { p.Services = []string{"artifactregistry.googleapis.com"} })
		}},
		{"gcp-wildcard-service", "restricted GCP service", func(in *intent.Intent) {
			editPerimeter(in, func(p *intent.GCPPerimeter) { p.Services = []string{"*.googleapis.com"} })
		}},
		{"gcp-empty-project-list", perimeter, func(in *intent.Intent) {
			editPerimeter(in, func(p *intent.GCPPerimeter) { p.Projects = nil })
		}},
		{"gcp-overlapping-perimeters", "multiply protected", func(in *intent.Intent) {
			in.GCP.Perimeters["overlap"] = in.GCP.Perimeters["billing_perimeter"]
		}},
		{"gcp-invalid-access-policy", perimeter, func(in *intent.Intent) {
			editPerimeter(in, func(p *intent.GCPPerimeter) { p.AccessPolicy = "accessPolicies/*" })
		}},
		{"gcp-project-alias", project, func(in *intent.Intent) { in.GCP.Projects["copy"] = in.GCP.Projects["billing-cloud"] }},
		{"gcp-resource-collision", project, func(in *intent.Intent) {
			in.GCP.Projects["imds"] = intent.GCPProject{ID: "second-project", Number: "1234"}
		}},
		{"gcp-agent-deputy", "Lethal Trifecta secret reachable", func(in *intent.Intent) { in.GCP.Bindings[0].Workload = "catalog" }},
		{"admission-empty-prefix-list", "admission requires registry prefixes", func(in *intent.Intent) { in.Workloads[0].Admission.RegistryPrefixes = nil }},
		{"admission-prefix-without-boundary", prefix, func(in *intent.Intent) { in.Workloads[0].Admission.RegistryPrefixes = []string{"registry.example.com"} }},
		{"admission-wildcard-prefix", prefix, func(in *intent.Intent) { in.Workloads[0].Admission.RegistryPrefixes = []string{"*.example.com/"} }},
		{"admission-duplicate-prefix", prefix, func(in *intent.Intent) {
			p := &in.Workloads[0].Admission.RegistryPrefixes
			*p = append(*p, (*p)[0])
		}},
		{"mcp-missing-agent", mcp, func(in *intent.Intent) { in.MCP[0].Agent = "missing" }},
		{"mcp-public-gateway", mcp, func(in *intent.Intent) { in.Workloads[1].Ingress = true }},
		{"mcp-cross-tenant-gateway", mcp, func(in *intent.Intent) { in.Workloads[1].Tenant = "other" }},
		{"mcp-upstream-is-metadata", mcp, func(in *intent.Intent) { in.MCP[0].Upstream = "imds" }},
		{"mcp-admission-missing", mcp, func(in *intent.Intent) { in.Workloads[1].Admission = nil }},
		{"mcp-executable-policy-missing", mcp, func(in *intent.Intent) { in.Workloads[0].ExecAllowlist = nil }},
		{"mcp-post-read-only", grant, func(in *intent.Intent) { in.MCP[0].Paths[1].Mode = intent.MCPReadOnly }},
		{"mcp-unknown-mode", grant, func(in *intent.Intent) { in.MCP[0].Paths[0].Mode = "always" }},
		{"mcp-path-wildcard", grant, func(in *intent.Intent) { in.MCP[0].Paths[0].Path = "/*" }},
		{"mcp-path-traversal", grant, func(in *intent.Intent) { in.MCP[0].Paths[0].Path = "/lookup/../admin" }},
		{"mcp-overlapping-grants", grant, func(in *intent.Intent) { in.MCP[0].Paths = append(in.MCP[0].Paths, in.MCP[0].Paths[0]) }},
		{"mcp-direct-egress-bypass", "conflicts with MCP confinement", func(in *intent.Intent) {
			in.Rules = append(in.Rules, intent.Rule{Pair: intent.Pair{From: "agent", To: "catalog-api"}, Kind: "dns", Port: 443})
		}},
		{"mcp-different-workload-bypass", "conflicts with dedicated MCP upstream", func(in *intent.Intent) {
			in.Rules = append(in.Rules, intent.Rule{Pair: intent.Pair{From: "reader", To: "catalog-api"}, Kind: "dns", Port: 8443})
		}},
		{"mcp-neverreach-sees-implicit-edge", "neverReach violated", func(in *intent.Intent) {
			in.NeverReach = append(in.NeverReach, intent.Pair{From: "agent", To: "catalog-api"})
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := wave6Fixture(t)
			tc.mutate(&in)
			for _, f := range prover.Check(in) {
				if strings.Contains(f.Property, tc.property) && len(f.Witness) > 0 && f.Witness[0] != "" {
					return
				}
			}
			t.Fatalf("missing denial witness for %q: %v", tc.property, prover.Check(in))
		})
	}
}

func TestWave6CleanTopologies(t *testing.T) {
	for _, name := range []string{"combined", "admission-only", "gcp-only", "mcp-only", "federated"} {
		t.Run(name, func(t *testing.T) {
			in := wave6Fixture(t)
			if name == "admission-only" || name == "mcp-only" {
				in.GCP = nil
				in.NeverReach = in.NeverReach[:len(in.NeverReach)-1]
			}
			if name == "admission-only" || name == "gcp-only" {
				in.MCP = nil
			}
			if name == "gcp-only" {
				for i := range in.Workloads {
					in.Workloads[i].Admission = nil
				}
			}
			if name == "federated" {
				in.Federation = &intent.Federation{TrustDomains: map[string]intent.TrustDomain{
					in.TrustDomain:     {Cluster: "east", SPIREParent: in.SPIREParent, BundleEndpoint: "https://east.example.com"},
					"west.example.org": {Cluster: "west", SPIREParent: "spiffe://west.example.org/spire/agent/production", BundleEndpoint: "https://west.example.com"},
				}}
				in.Workloads[2].TrustDomain = "west.example.org"
			}
			first, err := compiler.Compile(in)
			if err != nil {
				t.Fatal(err)
			}
			slices.Reverse(in.Workloads)
			slices.Reverse(in.Rules)
			for _, m := range in.MCP {
				slices.Reverse(m.Paths)
			}
			second, err := compiler.Compile(in)
			if err != nil || !reflect.DeepEqual(first, second) {
				t.Fatalf("nondeterministic compile: %v", err)
			}
		})
	}
}
