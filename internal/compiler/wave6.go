package compiler

import (
	"cmp"
	"encoding/json"
	"slices"
	"strconv"

	"github.com/cuhawk/AegisMesh/internal/intent"
)

type MCPAuthorization struct {
	Principal string `json:"principal"`
	Gateway   string `json:"gateway"`
	Upstream  string `json:"upstream"`
	intent.MCPPath
}

func mcpAuthorizations(in intent.Intent, workloads map[string]intent.Workload, resources map[string]intent.Resource) []MCPAuthorization {
	var result []MCPAuthorization
	for _, m := range in.MCP {
		for _, p := range m.Paths {
			result = append(result, MCPAuthorization{
				Principal: workloads[m.Agent].SPIFFEID(in.TrustDomain),
				Gateway:   workloads[m.Gateway].SPIFFEID(in.TrustDomain),
				Upstream:  resources[m.Upstream].Value,
				MCPPath:   p,
			})
		}
	}
	slices.SortFunc(result, func(a, b MCPAuthorization) int {
		return cmp.Or(cmp.Compare(a.Principal, b.Principal), cmp.Compare(a.Method, b.Method), cmp.Compare(a.Path, b.Path))
	})
	return result
}

func admissionPolicy(w intent.Workload) object {
	prefixes := slices.Clone(w.Admission.RegistryPrefixes)
	slices.Sort(prefixes)
	registries, _ := json.Marshal(prefixes)
	serviceAccount := strconv.Quote(w.ServiceAccount)
	workload := strconv.Quote(w.ID)
	label := `(has(object.metadata.labels) && "aegismesh.io/workload" in object.metadata.labels && object.metadata.labels["aegismesh.io/workload"] == ` + workload + ")"
	account := `(has(object.spec.serviceAccountName) ? object.spec.serviceAccountName : "default") == ` + serviceAccount
	return manifest("policies.kyverno.io/v1beta1", "ValidatingPolicy", w.Namespace+"."+w.ID, "", object{
		"failurePolicy":     "Fail",
		"validationActions": []string{"Deny"},
		"matchConstraints": object{"resourceRules": []object{{
			"apiGroups": []string{""}, "apiVersions": []string{"v1"},
			"operations": []string{"CREATE", "UPDATE"}, "resources": []string{"pods", "pods/ephemeralcontainers"},
		}}},
		"matchConditions": []object{{
			"name":       "managed-workload",
			"expression": "request.namespace == " + strconv.Quote(w.Namespace) + " && (" + account + " || " + label + ")",
		}},
		"variables": []object{
			{"name": "prefixes", "expression": string(registries)},
			{"name": "podNonRoot", "expression": "has(object.spec.securityContext) && has(object.spec.securityContext.runAsNonRoot) && object.spec.securityContext.runAsNonRoot"},
		},
		"validations": append([]object{
			{"expression": label + " && (" + account + ")", "message": "The workload label and service account must match intent."},
			{"expression": "(!has(object.spec.hostNetwork) || !object.spec.hostNetwork) && (!has(object.spec.hostPID) || !object.spec.hostPID) && (!has(object.spec.hostIPC) || !object.spec.hostIPC)", "message": "Host network, PID and IPC namespaces are forbidden."},
			{"expression": "!has(object.spec.volumes) || object.spec.volumes.all(v, !has(v.hostPath))", "message": "hostPath volumes are forbidden."},
			{"expression": "!has(object.spec.securityContext) || !has(object.spec.securityContext.runAsUser) || object.spec.securityContext.runAsUser > 0", "message": "The pod must not declare UID zero."},
		}, containerValidations()...),
	})
}

func containerValidations() []object {
	// Evaluate each list separately so CEL can type-check EphemeralContainer
	// and Container without concatenating distinct Kubernetes types.
	var validations []object
	const hardened = `has(c.securityContext) &&
		(has(c.securityContext.runAsNonRoot) ? c.securityContext.runAsNonRoot : variables.podNonRoot) &&
		(!has(c.securityContext.runAsUser) || c.securityContext.runAsUser > 0) &&
		has(c.securityContext.readOnlyRootFilesystem) && c.securityContext.readOnlyRootFilesystem &&
		(!has(c.securityContext.privileged) || !c.securityContext.privileged) &&
		has(c.securityContext.allowPrivilegeEscalation) && !c.securityContext.allowPrivilegeEscalation`
	for _, field := range []string{"containers", "initContainers", "ephemeralContainers"} {
		list := "object.spec." + field
		validations = append(validations,
			object{"expression": "!has(" + list + ") || " + list + ".all(c, " + hardened + ")",
				"message": field + " must run as non-root with a read-only root filesystem and no privilege escalation."},
			object{"expression": "!has(" + list + ") || " + list + ".all(c, variables.prefixes.exists(prefix, c.image.startsWith(prefix)))",
				"message": field + " must use an allowed registry prefix."})
	}
	return validations
}

// The sockaddr argument presents the requested endpoint as SAddr/SPort in
// Tetragon. Cilium handles DNS/IP isolation and the gateway handles HTTP.
func mcpSocketGuard() []object {
	return []object{{
		"call": "security_socket_connect", "syscall": false,
		"args": []object{{"index": 0, "type": "socket"}, {"index": 1, "type": "sockaddr"}},
		"selectors": []object{{
			"matchArgs": []object{
				{"index": 0, "operator": "Protocol", "values": []string{"IPPROTO_TCP"}},
				{"index": 1, "operator": "Family", "values": []string{"AF_INET", "AF_INET6"}},
				{"index": 1, "operator": "SPort", "values": []string{"443"}},
			},
			"matchActions": []object{{"action": "Override", "argError": -13}},
		}},
	}}
}
