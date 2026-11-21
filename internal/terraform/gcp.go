package terraform

import (
	"fmt"
	"slices"
	"strings"

	"github.com/cuhawk/AegisMesh/internal/intent"
)

// addGCP renders reviewed project-role bindings and enforced VPC Service
// Controls perimeters into the same Terraform configuration as AWS.
func addGCP(config Object, in intent.Intent) {
	g := in.GCP
	if g == nil {
		return
	}
	workloads := make(map[string]intent.Workload, len(in.Workloads))
	for _, w := range in.Workloads {
		workloads[w.ID] = w
	}
	type scope struct{ project, role string }
	members := make(map[scope][]string)
	for _, b := range g.Bindings {
		p, w := g.Projects[b.Project], workloads[b.Workload]
		key := scope{b.Project, b.Role}
		members[key] = append(members[key], fmt.Sprintf(
			"principal://iam.googleapis.com/projects/%s/locations/global/workloadIdentityPools/%s.svc.id.goog/subject/ns/%s/sa/%s",
			p.Number, p.ID, w.Namespace, w.ServiceAccount))
	}
	bindings := Object{}
	for key, principals := range members {
		slices.Sort(principals)
		// The prover permits only a fixed set of predefined read roles.
		name := key.project + "-" + strings.ReplaceAll(strings.TrimPrefix(key.role, "roles/"), ".", "-")
		bindings[name] = Object{"project": g.Projects[key.project].ID, "role": key.role, "members": principals}
	}

	perimeters := Object{}
	for name, p := range g.Perimeters {
		parent := "accessPolicies/" + p.AccessPolicy
		projects := make([]string, 0, len(p.Projects))
		for _, project := range p.Projects {
			projects = append(projects, "projects/"+g.Projects[project].Number)
		}
		services := slices.Clone(p.Services)
		slices.Sort(projects)
		slices.Sort(services)
		perimeters[name] = Object{
			"parent": parent, "name": parent + "/servicePerimeters/" + name, "title": name,
			"perimeter_type": "PERIMETER_TYPE_REGULAR",
			"status":         Object{"resources": projects, "restricted_services": services},
		}
	}
	config["terraform"].(Object)["required_providers"].(Object)["google"] = Object{
		"source": "hashicorp/google", "version": "~> 6.0",
	}
	resources := config["resource"].(Object)
	resources["google_project_iam_binding"] = bindings
	resources["google_access_context_manager_service_perimeter"] = perimeters
}
