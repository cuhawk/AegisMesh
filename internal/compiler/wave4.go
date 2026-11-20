package compiler

import (
	"slices"

	"github.com/cuhawk/AegisMesh/internal/intent"
)

// ClusterArtifacts are the deployment artifacts for one trust domain.
type ClusterArtifacts struct {
	TrustDomain    string            `json:"trustDomain"`
	BundleEndpoint string            `json:"bundleEndpoint"`
	TrustedBundles map[string]string `json:"trustedBundles"`
	Kubernetes     []object          `json:"kubernetes"`
	CiliumHTTP     []object          `json:"ciliumHTTP"`
	SPIRE          []object          `json:"spire"`
	Tetragon       []object          `json:"tetragon,omitempty"`
}

func federationBindings(in intent.Intent) map[string]*ClusterArtifacts {
	if in.Federation == nil {
		return nil
	}
	result := make(map[string]*ClusterArtifacts)
	for domain, d := range in.Federation.TrustDomains {
		bundles := make(map[string]string)
		for _, peer := range d.Trusts {
			bundles[peer] = in.Federation.TrustDomains[peer].BundleEndpoint
		}
		result[d.Cluster] = &ClusterArtifacts{
			TrustDomain: domain, BundleEndpoint: d.BundleEndpoint, TrustedBundles: bundles,
			SPIRE: []object{},
		}
	}
	return result
}

func executionPolicy(w intent.Workload) object {
	binaries := slices.Clone(w.ExecAllowlist)
	slices.Sort(binaries)
	return manifest("cilium.io/v1alpha1", "TracingPolicyNamespaced", w.ID, w.Namespace, object{
		"podSelector": object{"matchLabels": object{"aegismesh.io/workload": w.ID}},
		"lsmhooks": []object{{
			"hook": "bprm_check_security",
			"args": []object{{"index": 0, "type": "linux_binprm"}},
			"selectors": []object{{
				"matchArgs":    []object{{"index": 0, "operator": "NotEqual", "values": binaries}},
				"matchActions": []object{{"action": "Override", "argError": -13}},
			}},
		}},
	})
}
