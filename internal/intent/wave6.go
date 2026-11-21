package intent

// GCP models project-level read grants and enforced service perimeters.
type GCP struct {
	Projects   map[string]GCPProject   `json:"projects"`
	Bindings   []GCPBinding            `json:"bindings"`
	Perimeters map[string]GCPPerimeter `json:"perimeters"`
}

type GCPProject struct {
	ID     string `json:"id"`
	Number string `json:"number"`
}

type GCPBinding struct {
	Workload string `json:"workload"`
	Project  string `json:"project"`
	Role     string `json:"role"`
}

type GCPPerimeter struct {
	AccessPolicy string   `json:"accessPolicy"`
	Projects     []string `json:"projects"`
	Services     []string `json:"services"`
}

// Admission enables the full pod hardening baseline for a workload.
type Admission struct {
	RegistryPrefixes []string `json:"registryPrefixes"`
}

// MCP connects an agent to a dedicated policy enforcement gateway.
type MCP struct {
	Agent    string    `json:"agent"`
	Gateway  string    `json:"gateway"`
	Upstream string    `json:"upstream"` // ID of an exact fqdn resource
	Paths    []MCPPath `json:"paths"`
}

type MCPPath struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Mode   string `json:"mode"`
}

const (
	MCPPort          = 8080
	MCPReadOnly      = "read-only"
	MCPApprovalGated = "approval-gated"
)

// WithMCPRules expands implicit gateway edges for the shared graph and compiler.
// The caller validates declared rules before expanding them.
func (in Intent) WithMCPRules() Intent {
	if len(in.MCP) == 0 {
		return in
	}
	rules := append([]Rule(nil), in.Rules...)
	for _, m := range in.MCP {
		for _, p := range m.Paths {
			rules = append(rules, Rule{Pair: Pair{From: m.Agent, To: m.Gateway},
				Kind: "http", Port: MCPPort, Method: p.Method, Path: p.Path})
		}
		rules = append(rules, Rule{Pair: Pair{From: m.Gateway, To: m.Upstream},
			Kind: "dns", Port: 443, ApprovedEgress: true})
	}
	in.Rules = rules
	return in
}
