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

const westDomain = "west.example.org"

func wave4Fixture(t *testing.T) intent.Intent {
	t.Helper()
	f, err := os.Open("../../examples/wave4.json")
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

func changeWest(in *intent.Intent, change func(*intent.TrustDomain)) {
	west := in.Federation.TrustDomains[westDomain]
	change(&west)
	in.Federation.TrustDomains[westDomain] = west
}

func TestWave4HostileMutations(t *testing.T) {
	tests := []struct {
		name, property, witness string
		mutate                  func(*intent.Intent)
	}{
		{"missing local binding", "federation requires multiple domains", "cluster.local", func(in *intent.Intent) {
			delete(in.Federation.TrustDomains, in.TrustDomain)
		}},
		{"cluster collision", "cluster bound to multiple trust domains", "east -> cluster.local -> west.example.org", func(in *intent.Intent) {
			changeWest(in, func(t *intent.TrustDomain) { t.Cluster = "east" })
		}},
		{"bundle endpoint collision", "bundle endpoint shared by multiple trust domains", "https://bundle.east.example.org:8443 -> cluster.local -> west.example.org", func(in *intent.Intent) {
			changeWest(in, func(t *intent.TrustDomain) {
				t.BundleEndpoint = in.Federation.TrustDomains[in.TrustDomain].BundleEndpoint
			})
		}},
		{"plaintext bundle endpoint", "invalid federated trust-domain binding", "west.example.org -> west -> spiffe://west.example.org/spire/agent/production -> http://bundle.west.example.org", func(in *intent.Intent) {
			changeWest(in, func(t *intent.TrustDomain) { t.BundleEndpoint = "http://bundle.west.example.org" })
		}},
		{"parent in a different domain", "invalid federated trust-domain binding", "west.example.org -> west -> spiffe://cluster.local/spire/agent/production -> https://bundle.west.example.org:8443", func(in *intent.Intent) {
			changeWest(in, func(t *intent.TrustDomain) { t.SPIREParent = in.SPIREParent })
		}},
		{"dangling bundle trust", "invalid or duplicate bundle trust", "west.example.org -> unknown.example.org", func(in *intent.Intent) {
			changeWest(in, func(t *intent.TrustDomain) { t.Trusts = append(t.Trusts, "unknown.example.org") })
		}},
		{"self bundle trust", "invalid or duplicate bundle trust", "west.example.org -> west.example.org", func(in *intent.Intent) {
			changeWest(in, func(t *intent.TrustDomain) { t.Trusts = append(t.Trusts, westDomain) })
		}},
		{"one-way trust", "cross-domain edge requires HTTP and mutual bundle trust", "catalog -> cluster.local -> west.example.org -> mirror", func(in *intent.Intent) {
			changeWest(in, func(t *intent.TrustDomain) { t.Trusts = nil })
		}},
		{"unknown workload domain", "unknown workload trust domain", "catalog-tool -> unknown.example.org", func(in *intent.Intent) {
			in.Workloads[3].TrustDomain = "unknown.example.org"
		}},
		{"remote workload without federation", "workload trust domain requires federation", "catalog-tool -> west.example.org", func(in *intent.Intent) {
			in.Federation = nil
		}},
		{"missing direct reachability grant", "unauthorized cross-domain reachability", "agent -> catalog-tool", func(in *intent.Intent) {
			in.Federation.AllowReach = in.Federation.AllowReach[1:]
		}},
		{"missing transitive reachability grant", "unauthorized cross-domain reachability", "agent -> catalog -> mirror", func(in *intent.Intent) {
			in.Federation.AllowReach = slices.Delete(in.Federation.AllowReach, 2, 3)
		}},
		{"new reverse path", "unauthorized cross-domain reachability", "mirror -> catalog", func(in *intent.Intent) {
			r := in.Rules[0]
			r.From, r.To = "mirror", "catalog"
			in.Rules = append(in.Rules, r)
		}},
		{"cross-tenant federation grant", "invalid or duplicate federated reachability grant", "reader -> mirror", func(in *intent.Intent) {
			in.Federation.AllowReach = append(in.Federation.AllowReach, intent.Pair{From: "reader", To: "mirror"})
		}},
		{"cross-domain proxy", "cross-domain edge requires HTTP and mutual bundle trust", "catalog -> cluster.local -> west.example.org -> mirror", func(in *intent.Intent) {
			in.Rules = append(in.Rules, link("catalog", "mirror", "proxy"))
		}},
		{"neverReach overrides grant", "neverReach violated", "agent -> catalog -> mirror", func(in *intent.Intent) {
			in.NeverReach = append(in.NeverReach, intent.Pair{From: "agent", To: "mirror"})
		}},
		{"empty exec allowlist", "empty executable allowlist", "agent", func(in *intent.Intent) {
			in.Workloads[0].ExecAllowlist = []string{}
		}},
		{"relative executable", "invalid or duplicate executable path", "agent -> bin/agent", func(in *intent.Intent) {
			in.Workloads[0].ExecAllowlist[0] = "bin/agent"
		}},
		{"glob executable", "invalid or duplicate executable path", "agent -> /usr/bin/*", func(in *intent.Intent) {
			in.Workloads[0].ExecAllowlist[0] = "/usr/bin/*"
		}},
		{"traversal executable", "invalid or duplicate executable path", "agent -> /usr/bin/../agent", func(in *intent.Intent) {
			in.Workloads[0].ExecAllowlist[0] = "/usr/bin/../agent"
		}},
		{"duplicate executable", "invalid or duplicate executable path", "agent -> /usr/local/bin/catalog-agent", func(in *intent.Intent) {
			in.Workloads[0].ExecAllowlist = append(in.Workloads[0].ExecAllowlist, in.Workloads[0].ExecAllowlist[0])
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := wave4Fixture(t)
			tt.mutate(&in)
			if _, err := compiler.Compile(in); err == nil {
				t.Fatal("compiler emitted policy for an unsafe intent")
			}
			for _, finding := range prover.Check(in) {
				if strings.HasPrefix(finding.Property, tt.property) && strings.Join(finding.Witness, " -> ") == tt.witness {
					return
				}
			}
			t.Fatalf("missing %q witness %q in %v", tt.property, tt.witness, prover.Check(in))
		})
	}
}

func TestWave4CleanTopologies(t *testing.T) {
	for _, name := range []string{"federated-tool-and-gateway", "independent-clusters", "local-runtime-policy"} {
		t.Run(name, func(t *testing.T) {
			in := wave4Fixture(t)
			if name == "independent-clusters" {
				in.Federation.AllowReach = nil
				for domain, binding := range in.Federation.TrustDomains {
					binding.Trusts = nil
					in.Federation.TrustDomains[domain] = binding
				}
				in.Rules = slices.DeleteFunc(in.Rules, func(r intent.Rule) bool { return r.To == "mirror" || r.To == "catalog-tool" })
			}
			if name == "local-runtime-policy" {
				in = wave3Fixture(t)
				in.Workloads[0].ExecAllowlist = []string{"/usr/bin/tini", "/app/agent"}
			}
			first, err := compiler.Compile(in)
			if err != nil {
				t.Fatal(err)
			}
			slices.Reverse(in.Workloads)
			slices.Reverse(in.Rules)
			second, err := compiler.Compile(in)
			if err != nil || !reflect.DeepEqual(first, second) {
				t.Fatalf("nondeterministic compile, error %v", err)
			}
		})
	}
}
