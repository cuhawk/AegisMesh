package prover_test

import (
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/cuhawk/AegisMesh/internal/compiler"
	"github.com/cuhawk/AegisMesh/internal/intent"
	"github.com/cuhawk/AegisMesh/internal/prover"
)

func fixture(t *testing.T) intent.Intent {
	t.Helper()
	f, err := os.Open("../../examples/multitenant.json")
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

func link(from, to, kind string) intent.Rule {
	return intent.Rule{Pair: intent.Pair{From: from, To: to}, Kind: kind}
}

func TestHostileMutations(t *testing.T) {
	const wildcard = "invalid, wildcard or duplicate resource"
	const unexpected = "unexpected rule fields"
	tests := []struct {
		name, property, witness string
		mutate                  func(*intent.Intent)
	}{
		{"wildcard AWS DNS", wildcard, "catalog-api -> *.amazonaws.com", func(in *intent.Intent) { in.Resources[0].Value = "*.amazonaws.com" }},
		{"bare DNS wildcard", wildcard, "catalog-api -> *", func(in *intent.Intent) { in.Resources[0].Value = "*" }},
		{"IP disguised as DNS", wildcard, "catalog-api -> 169.254.169.254", func(in *intent.Intent) { in.Resources[0].Value = "169.254.169.254" }},
		{"IPv6 metadata alias", wildcard, "imds -> ::ffff:169.254.169.254", func(in *intent.Intent) { in.Resources[5].Value = "::ffff:169.254.169.254" }},
		{"redirect to metadata", "metadata reachable", "agent -> catalog -> catalog-api -> imds", func(in *intent.Intent) { in.Rules = append(in.Rules, link("catalog-api", "imds", "redirect")) }},
		{"metadata via proxy", "metadata reachable", "agent -> catalog -> imds", func(in *intent.Intent) { in.Rules = append(in.Rules, link("catalog", "imds", "proxy")) }},
		{"contained metadata address", "metadata reachable", "agent -> range", func(in *intent.Intent) {
			in.Resources = append(in.Resources, intent.Resource{ID: "range", Kind: "cidr", Value: "169.254.0.0/16"})
			in.Rules = append(in.Rules, link("agent", "range", "proxy"))
		}},
		{"IPv6 metadata transit", "metadata reachable", "agent -> ipv6", func(in *intent.Intent) {
			in.Resources = append(in.Resources, intent.Resource{ID: "ipv6", Kind: "metadata", Value: "fd00:ec2::254"})
			in.Rules = append(in.Rules, link("agent", "ipv6", "proxy"))
		}},
		{"shadowed HTTP allow", "allow shadowed by deny", "agent -> catalog", func(in *intent.Intent) {
			r := in.Rules[0]
			r.Deny = true
			in.Rules = append(in.Rules, r)
		}},
		{"wildcard HTTP path", "invalid or overly broad http rule", "agent -> catalog", func(in *intent.Intent) { in.Rules[0].Path = "/.*" }},
		{"wildcard HTTP method", "invalid or overly broad http rule", "agent -> catalog", func(in *intent.Intent) { in.Rules[0].Method = "*" }},
		{"HTTP traversal path", "noncanonical HTTP path", "agent -> catalog", func(in *intent.Intent) { in.Rules[0].Path = "/catalog/../secret" }},
		{"HTTP absent port", "invalid or overly broad http rule", "agent -> catalog", func(in *intent.Intent) { in.Rules[0].Port = 0 }},
		{"HTTP cross tenant", "cross-tenant HTTP allow", "agent -> reader", func(in *intent.Intent) { in.Rules[0].To = "reader" }},
		{"missing SVID TTL", "invalid or duplicate workload", "agent", func(in *intent.Intent) { in.Workloads[0].SVIDTTL = 0 }},
		{"long SVID TTL", "invalid or duplicate workload", "agent", func(in *intent.Intent) { in.Workloads[0].SVIDTTL = 3601 }},
		{"foreign SPIRE parent", "invalid SPIRE parent identity", "spiffe://external.local/spire/agent/x", func(in *intent.Intent) { in.SPIREParent = "spiffe://external.local/spire/agent/x" }},
		{"duplicate identity", "shared workload identity", "agent -> catalog", func(in *intent.Intent) { in.Workloads[1].ServiceAccount = "agent" }},
		{"missing OIDC subject", "invalid or overly broad assume rule", "reader -> reader-role", func(in *intent.Intent) { in.Rules[4].Subject = "" }},
		{"wildcard OIDC subject", "invalid or overly broad assume rule", "reader -> reader-role", func(in *intent.Intent) { in.Rules[4].Subject = "system:serviceaccount:*:*" }},
		{"wildcard audience", "invalid or overly broad assume rule", "reader -> reader-role", func(in *intent.Intent) { in.Rules[4].Audience = "*" }},
		{"foreign OIDC account", "invalid or overly broad assume rule", "reader -> reader-role", func(in *intent.Intent) {
			in.Rules[4].OIDCProvider = strings.Replace(in.Rules[4].OIDCProvider, "123456789012", "999999999999", 1)
		}},
		{"wildcard IAM resources", wildcard, "vault -> *", func(in *intent.Intent) { in.Resources[3].Value = "*" }},
		{"wildcard S3 action", "invalid or overly broad read rule", "reader-role -> vault", func(in *intent.Intent) { in.Rules[5].Action = "s3:*" }},
		{"IAM PassRole wildcard", "PassRole prohibited", "reader -> reader-role", func(in *intent.Intent) {
			r := link("reader", "reader-role", "pass")
			r.Action = "iam:PassRole"
			in.Rules = append(in.Rules, r)
			in.Resources[4].Value = "*"
		}},
		{"invalid role ARN", wildcard, "reader-role -> broken", func(in *intent.Intent) { in.Resources[4].Value = "broken" }},
		{"IPv4 allow all", wildcard, "range -> 0.0.0.0/0", func(in *intent.Intent) {
			in.Resources = append(in.Resources, intent.Resource{ID: "range", Kind: "cidr", Value: "0.0.0.0/0"})
		}},
		{"IPv6 allow all", wildcard, "range -> ::/0", func(in *intent.Intent) {
			in.Resources = append(in.Resources, intent.Resource{ID: "range", Kind: "cidr", Value: "::/0"})
		}},
		{"quarantined reader raw egress", "Lethal Trifecta unauthorized egress", "reader -> internet", func(in *intent.Intent) {
			in.Workloads[2].Untrusted = true
			in.Rules[2].ApprovedEgress = false
			in.Rules[3].ApprovedEgress = false
			in.Rules = slices.Delete(in.Rules, 2, 4)
			in.Rules = append(in.Rules, link("reader", "internet", "proxy"))
		}},
		{"confused deputy secret path", "neverReach violated", "agent -> catalog -> reader -> reader-role -> vault", func(in *intent.Intent) { in.Rules = append(in.Rules, link("catalog", "reader", "proxy")) }},
		{"quarantined reader FQDN egress", "Lethal Trifecta unauthorized egress", "reader -> sts-api", func(in *intent.Intent) {
			in.Workloads[2].Untrusted = true
			in.Rules[2].ApprovedEgress = false
			in.Rules[3].ApprovedEgress = false
		}},
		{"quarantined reader reaches approved FQDN through deputy", "Lethal Trifecta unauthorized egress", "reader -> catalog -> catalog-api", func(in *intent.Intent) {
			in.Workloads[2].Untrusted = true
			in.Rules = slices.Delete(in.Rules, 2, 4)
			in.Rules = append(in.Rules, link("reader", "catalog", "proxy"))
		}},
		{"agent self-approves egress", "invalid or overly broad dns rule", "agent -> catalog-api", func(in *intent.Intent) {
			in.Rules[1].From = "agent"
		}},
		{"unexpected OIDC on DNS", unexpected, "catalog -> catalog-api", func(in *intent.Intent) { in.Rules[1].Subject = "*" }},
		{"unknown destination", "unknown rule endpoint", "agent -> missing", func(in *intent.Intent) { in.Rules[0].To = "missing" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := fixture(t)
			tt.mutate(&in)
			found := prover.Check(in)
			if !slices.ContainsFunc(found, func(f prover.Finding) bool {
				return f.Property == tt.property && strings.Join(f.Witness, " -> ") == tt.witness
			}) {
				t.Fatalf("wanted %s: %s, got %v", tt.property, tt.witness, found)
			}
			if _, err := compiler.Compile(in); err == nil {
				t.Fatal("compiler emitted policy for a rejected intent")
			}
		})
	}
}

func TestCleanTopologies(t *testing.T) {
	for i := range 16 {
		t.Run(fmt.Sprintf("tenant-mesh-%02d", i), func(t *testing.T) {
			in := fixture(t)
			for j := range i + 4 {
				id := fmt.Sprintf("worker-%02d", j)
				in.Workloads = append(in.Workloads, intent.Workload{ID: id, Namespace: "research", ServiceAccount: id, Tenant: "research", SVIDTTL: 300 + j})
				r := link("catalog", id, "http")
				r.Method, r.Path, r.Port = "GET", "/status", 8080
				in.Rules = append(in.Rules, r)
				if j%2 == 0 {
					r.From, r.To, r.Method = id, "catalog", "POST"
					in.Rules = append(in.Rules, r)
				}
				in.NeverReach = append(in.NeverReach, intent.Pair{From: id, To: "vault"})
			}
			switch i % 4 {
			case 0:
				in.Rules = append(in.Rules, link("catalog-api", "catalog", "redirect"))
			case 1:
				r := in.Rules[0]
				r.Method, r.Deny = "POST", true
				in.Rules = append(in.Rules, r)
			case 2:
				in.Workloads[1].Ingress = true
			case 3:
				r := in.Rules[1]
				r.From, r.ApprovedEgress = "agent", false
				in.Rules = append(in.Rules, r)
			}
			if findings := prover.Check(in); len(findings) > 0 {
				t.Fatal(findings)
			}
			first, err := compiler.Compile(in)
			if err != nil {
				t.Fatal(err)
			}
			slices.Reverse(in.Workloads)
			slices.Reverse(in.Resources)
			slices.Reverse(in.Rules)
			second, err := compiler.Compile(in)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(first, second) {
				t.Fatal("reordering declarations changed the bundle")
			}
		})
	}
}

func TestShortestWitnessAndDenyPrecedence(t *testing.T) {
	in := fixture(t)
	in.Rules = append(in.Rules, link("catalog", "imds", "proxy"), link("agent", "imds", "proxy"))
	assertWitness := func(want string) {
		t.Helper()
		if !slices.ContainsFunc(prover.Check(in), func(f prover.Finding) bool {
			return f.Property == "metadata reachable" && strings.Join(f.Witness, " -> ") == want
		}) {
			t.Fatalf("missing shortest witness %s: %v", want, prover.Check(in))
		}
	}
	assertWitness("agent -> imds")
	deny := in.Rules[len(in.Rules)-1]
	deny.Deny = true
	in.Rules = append(in.Rules, deny)
	assertWitness("agent -> catalog -> imds")
}
