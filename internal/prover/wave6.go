package prover

import (
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/cuhawk/AegisMesh/internal/intent"
)

var (
	projectID     = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)
	cloudNumber   = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)
	perimeterName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,49}$`)
	registry      = regexp.MustCompile(`^([a-z0-9-]+\.)+[a-z0-9-]+(/[a-z0-9]+([._-][a-z0-9]+)*)*/$`)
	readServices  = map[string]string{
		"roles/storage.objectViewer":    "storage.googleapis.com",
		"roles/artifactregistry.reader": "artifactregistry.googleapis.com",
	}
)

func checkAdmission(w intent.Workload, add func(string, ...string)) {
	if w.Admission == nil {
		return
	}
	prefixes := w.Admission.RegistryPrefixes
	if len(prefixes) == 0 {
		add("admission requires registry prefixes", w.ID)
	}
	seen := make(map[string]bool)
	for _, prefix := range prefixes {
		host, _, _ := strings.Cut(prefix, "/")
		if len(prefix) > 253 || !registry.MatchString(prefix) || !domain(host) || seen[prefix] {
			add("invalid or duplicate image registry prefix", w.ID, prefix)
		}
		seen[prefix] = true
	}
}

func checkGCP(in intent.Intent, kinds map[string]string, workloads map[string]intent.Workload, add func(string, ...string)) {
	g := in.GCP
	if g == nil {
		return
	}
	if len(g.Projects) == 0 || len(g.Bindings) == 0 || len(g.Perimeters) == 0 {
		add("GCP requires projects, bindings and service perimeters", "gcp")
	}
	ids, numbers := make(map[string]bool), make(map[string]bool)
	for _, name := range slices.Sorted(maps.Keys(g.Projects)) {
		p := g.Projects[name]
		if !label.MatchString(name) || kinds[name] != "" || !projectID.MatchString(p.ID) ||
			!cloudNumber.MatchString(p.Number) || ids[p.ID] || numbers[p.Number] {
			add("invalid or duplicate GCP project", name, p.ID, p.Number)
		}
		ids[p.ID], numbers[p.Number] = true, true
	}
	perimeters := make(map[string]string)
	restricted := make(map[string]map[string]bool)
	for _, name := range slices.Sorted(maps.Keys(g.Perimeters)) {
		p := g.Perimeters[name]
		if !perimeterName.MatchString(name) || !cloudNumber.MatchString(p.AccessPolicy) || len(p.Projects) == 0 || len(p.Services) == 0 {
			add("invalid GCP service perimeter", name, p.AccessPolicy)
		}
		services := make(map[string]bool)
		for _, service := range p.Services {
			if (service != "storage.googleapis.com" && service != "artifactregistry.googleapis.com") || services[service] {
				add("invalid or duplicate restricted GCP service", name, service)
			}
			services[service] = true
		}
		for _, project := range p.Projects {
			if _, exists := g.Projects[project]; !exists || perimeters[project] != "" {
				add("unknown or multiply protected GCP project", name, project)
			}
			perimeters[project], restricted[project] = name, services
		}
	}
	for _, name := range slices.Sorted(maps.Keys(g.Projects)) {
		if perimeters[name] == "" {
			add("GCP project outside a service perimeter", name)
		}
	}
	bindings := make(map[intent.GCPBinding]bool)
	for _, binding := range g.Bindings {
		w := workloads[binding.Workload]
		if w.ID == "" || w.Untrusted || w.Ingress || !restricted[binding.Project][readServices[binding.Role]] || bindings[binding] {
			add("invalid, duplicate or unprotected GCP IAM binding", binding.Workload, binding.Project, binding.Role)
		}
		if in.Federation != nil {
			for _, other := range in.Workloads {
				if other.ID != w.ID && other.Namespace == w.Namespace && other.ServiceAccount == w.ServiceAccount {
					add("GCP workload identity is shared across clusters", binding.Workload, other.ID)
				}
			}
		}
		bindings[binding] = true
	}
}

func checkMCP(in intent.Intent, workloads map[string]intent.Workload, resources map[string]intent.Resource, add func(string, ...string)) {
	owners := make(map[string]bool)
	for _, m := range in.MCP {
		agent, gateway := workloads[m.Agent], workloads[m.Gateway]
		upstream := resources[m.Upstream]
		if agent.ID == "" || !agent.Untrusted || gateway.ID == "" || gateway.Untrusted || gateway.Ingress || gateway.ToolScope != "" ||
			agent.ID == gateway.ID || agent.Tenant != gateway.Tenant || agent.Domain(in.TrustDomain) != gateway.Domain(in.TrustDomain) ||
			owners[m.Agent] || owners[m.Gateway] || agent.Admission == nil || gateway.Admission == nil ||
			len(agent.ExecAllowlist) == 0 || len(gateway.ExecAllowlist) == 0 || upstream.Kind != "fqdn" || len(m.Paths) == 0 {
			add("invalid MCP agent, dedicated gateway or upstream", m.Agent, m.Gateway, m.Upstream)
		}
		owners[m.Agent], owners[m.Gateway] = true, true
		seen := make(map[[2]string]bool)
		for _, p := range m.Paths {
			key := [2]string{p.Method, p.Path}
			read := p.Method == "GET" || p.Method == "HEAD"
			if !canonicalPath(p.Path) || len(p.Path) > 255 || !slices.Contains(methods, p.Method) ||
				(p.Mode != intent.MCPApprovalGated && (p.Mode != intent.MCPReadOnly || !read)) || seen[key] {
				add("invalid or duplicate MCP path grant", m.Agent, p.Method, p.Path, p.Mode)
			}
			seen[key] = true
		}
		for _, r := range in.Rules {
			// Generated edges own the gateway exclusively. An explicit deny
			// touching the gateway or the agent's outbound edges also conflicts.
			if r.From == m.Agent || r.From == m.Gateway || r.To == m.Gateway {
				add("explicit rule conflicts with MCP confinement", r.From, r.To)
			}
		}
		for _, other := range in.MCP {
			if other.Gateway != m.Gateway && other.Upstream == m.Upstream {
				add("MCP upstream shared by dedicated gateways", m.Gateway, other.Gateway, m.Upstream)
			}
		}
		for _, r := range in.Rules {
			if !r.Deny && (r.From == m.Upstream || r.To == m.Upstream) {
				add("explicit rule conflicts with dedicated MCP upstream", r.From, r.To)
			}
		}
	}
}
