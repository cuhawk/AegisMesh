package aegismesh

import rego.v1

default allow := false

allow if {
	count(deny) == 0
}

required_cidrs := {"169.254.169.254/32", "fd00:ec2::254/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}

deny contains "missing policy bundle" if {
	not is_array(input.kubernetes)
}

deny contains "missing Cilium HTTP bundle" if {
	not is_array(input.ciliumHTTP)
}

deny contains "missing IAM documents" if {
	not is_object(input.iam)
}

deny contains "missing SPIRE entries" if {
	not is_array(input.spire)
}

deny contains "missing cluster isolation" if {
	not isolation_present(input.kubernetes)
}

deny contains "missing Cilium HTTP cluster isolation" if {
	not isolation_present(input.ciliumHTTP)
}

policies := array.concat(input.kubernetes, input.ciliumHTTP)

isolation_present(profile) if {
	some policy in profile
	policy.kind == "CiliumClusterwideNetworkPolicy"
	policy.metadata.name == "aegismesh-isolation"
	policy.spec.enableDefaultDeny == {"ingress": true, "egress": true}
	policy.spec.ingress == [{"fromEntities": ["none"]}]
	policy.spec.egress == [{"toEntities": ["none"]}]
	policy.spec.endpointSelector == {"matchExpressions": [{"key": "k8s:aegismesh.io/workload", "operator": "Exists"}]}
	cidrs := {cidr | some rule in policy.spec.egressDeny; some cidr in rule.toCIDR}
	count(required_cidrs - cidrs) == 0
}

valid_svid(entry) if {
	is_number(entry.x509_svid_ttl)
	entry.x509_svid_ttl >= 1
	entry.x509_svid_ttl <= 3600
	regex.match("^spiffe://[a-z0-9.-]+/ns/[a-z0-9-]+/sa/[a-z0-9-]+$", entry.spiffe_id)
}

deny contains msg if {
	some entry in input.spire
	not valid_svid(entry)
	msg := sprintf("invalid SVID: %v", [entry])
}

deny contains msg if {
	some policy in policies
	policy.kind == "PeerAuthentication"
	object.get(object.get(policy.spec, "mtls", {}), "mode", "") != "STRICT"
	msg := sprintf("non-strict mTLS: %s", [policy.metadata.name])
}

deny contains msg if {
	some policy in policies
	some rule in object.get(policy.spec, "egress", [])
	some dns in object.get(rule, "toFQDNs", [])
	not regex.match("^[a-z0-9-]+(\\.[a-z0-9-]+)+$", object.get(dns, "matchName", ""))
	msg := sprintf("unscoped FQDN: %s", [policy.metadata.name])
}

deny contains msg if {
	some policy in policies
	some rule in object.get(policy.spec, "egress", [])
	rule.toEntities[_] in {"world", "all", "cluster"}
	msg := sprintf("broad entity egress: %s", [policy.metadata.name])
}

deny contains msg if {
	some policy in policies
	policy.kind == "AuthorizationPolicy"
	object.get(policy.spec, "action", "ALLOW") in {"ALLOW", "DENY"}
	some rule in object.get(policy.spec, "rules", [])
	not scoped_http(rule)
	msg := sprintf("unscoped authorization: %s", [policy.metadata.name])
}

scoped_http(rule) if {
	count(rule.from) == 1
	count(rule.to) == 1
	count(rule.from[0].source.principals) == 1
	regex.match("^[a-z0-9.-]+/ns/[a-z0-9-]+/sa/[a-z0-9-]+$", rule.from[0].source.principals[0])
	count(rule.to[0].operation.methods) == 1
	rule.to[0].operation.methods[0] in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
	count(rule.to[0].operation.paths) == 1
	regex.match("^(/[A-Za-z0-9._~-]+)*/?$", rule.to[0].operation.paths[0])
	count(rule.to[0].operation.ports) == 1
	regex.match("^[0-9]+$", rule.to[0].operation.ports[0])
}

deny contains msg if {
	some name, policy in input.iam
	some statement in policy.Statement
	not scoped_statement(statement)
	msg := sprintf("unscoped IAM statement: %s", [name])
}

scoped_statement(s) if {
	s.Effect == "Allow"
	s.Action == ["secretsmanager:GetSecretValue"]
	s.Condition == {"Bool": {"aws:SecureTransport": "true"}}
	count(s.Resource) == 1
	regex.match("^arn:aws:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]+$", s.Resource[0])
}

scoped_statement(s) if {
	s.Effect == "Allow"
	s.Action == ["s3:GetObject"]
	s.Condition == {"Bool": {"aws:SecureTransport": "true"}}
	count(s.Resource) == 1
	regex.match("^arn:aws:s3:::[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]/[A-Za-z0-9._/-]+$", s.Resource[0])
}

scoped_statement(s) if {
	s.Effect == "Allow"
	s.Action == ["sts:AssumeRoleWithWebIdentity"]
	regex.match("^arn:aws:iam::[0-9]{12}:oidc-provider/[A-Za-z0-9./_-]+$", s.Principal.Federated)
	issuer := split(s.Principal.Federated, "oidc-provider/")[1]
	count(s.Condition.StringEquals) == 2
	s.Condition.StringEquals[concat("", [issuer, ":aud"])] == "sts.amazonaws.com"
	regex.match("^system:serviceaccount:[a-z0-9-]+:[a-z0-9-]+$", s.Condition.StringEquals[concat("", [issuer, ":sub"])])
}

deny contains msg if {
	some name, policy in input.iam
	not valid_document(policy)
	msg := sprintf("invalid IAM document: %s", [name])
}

valid_document(policy) if {
	policy.Version == "2012-10-17"
	is_array(policy.Statement)
	count(policy.Statement) > 0
}

deny contains msg if {
	some policy in policies
	policy.kind == "CiliumNetworkPolicy"
	policy.spec.enableDefaultDeny != {"ingress": true, "egress": true}
	msg := sprintf("missing workload isolation: %s", [policy.metadata.name])
}

deny contains msg if {
	some policy in policies
	some rule in object.get(policy.spec, "egress", [])
	some cidr in object.get(rule, "toCIDR", [])
	msg := sprintf("direct CIDR egress: %s (%s)", [policy.metadata.name, cidr])
}

deny contains msg if {
	some policy in input.ciliumHTTP
	policy.kind == "CiliumNetworkPolicy"
	some rule in policy.spec.ingress
	rule != {"fromEntities": ["none"]}
	not strict_cilium_http(rule)
	msg := sprintf("missing Cilium HTTP allowlist: %s", [policy.metadata.name])
}

strict_cilium_http(rule) if {
	count(rule.fromEndpoints) == 1
	valid_cilium_peer_labels(rule.fromEndpoints[0].matchLabels)
	rule.fromEndpoints[0].matchLabels["k8s:io.kubernetes.pod.namespace"] != ""
	rule.fromEndpoints[0].matchLabels["io.cilium.k8s.policy.serviceaccount"] != ""
	count(rule.toPorts) == 1
	count(rule.toPorts[0].rules.http) == 1
	http := rule.toPorts[0].rules.http[0]
	http.method in {"^GET$", "^HEAD$", "^POST$", "^PUT$", "^PATCH$", "^DELETE$", "^OPTIONS$"}
	startswith(http.path, "^/")
	endswith(http.path, "$")
	not contains(http.path, "*")
}

valid_cilium_peer_labels(labels) if {
	count(object.get(input, "clusters", {})) == 0
	count(labels) == 2
}

valid_cilium_peer_labels(labels) if {
	count(labels) == 3
	cluster := labels["io.cilium.k8s.policy.cluster"]
	is_object(input.clusters[cluster])
}

deny contains msg if {
	some name, cluster in object.get(input, "clusters", {})
	some profile in ["kubernetes", "ciliumHTTP"]
	not isolation_present(cluster[profile])
	msg := sprintf("missing isolation: %s/%s", [name, profile])
}

deny contains "invalid Terraform IAM configuration" if {
	not is_object(input.terraform.resource.aws_iam_role)
}

deny contains "invalid Terraform inline policies" if {
	not is_object(input.terraform.resource.aws_iam_role_policy)
}

deny contains msg if {
	some kind, _ in input.terraform.resource
	not kind in reviewed_terraform_kinds
	msg := sprintf("unreviewed Terraform resource: %s", [kind])
}

deny contains msg if {
	some name, role in input.terraform.resource.aws_iam_role
	not matches_iam(name, "-trust", object.get(role, "assume_role_policy", ""))
	msg := sprintf("Terraform trust document differs from gated IAM: %s", [name])
}

deny contains msg if {
	some name, role in input.terraform.resource.aws_iam_role_policy
	not matches_iam(name, "-access", object.get(role, "policy", ""))
	msg := sprintf("Terraform inline policy differs from gated IAM: %s", [name])
}

matches_iam(name, suffix, body) if {
	key := concat("", [replace(name, "_", "-"), suffix])
	json.unmarshal(body) == input.iam[key]
}

# Runtime query. The caller supplies claims only after verifying the JWT-SVID
# signature, lifetime and issuer, and gets the peer principal from mTLS.
default allow_tool := false

allow_tool if {
	some edge in data.aegismesh_tool_authorizations
	input.namespace == edge.namespace
	input.tool == edge.tool
	input.peer_principal == edge.principal
	input.method == edge.method
	input.path == edge.path
	input.port == edge.port
	input.claims.iss == edge.issuer
	input.claims.sub == edge.subject
	audience_matches(input.claims.aud, edge.audience)
	input.claims.model_id == edge.model_id
	is_array(input.claims.tool_scopes)
	edge.tool_scope in input.claims.tool_scopes
	input.claims.delegator_sub == edge.delegator_sub
}

audience_matches(aud, expected) if aud == expected

audience_matches(aud, expected) if {
	is_array(aud)
	expected in aud
}

tool_rule(edge) := {
	"from": [{"source": {"principals": [edge.principal]}}],
	"to": [{"operation": {"methods": [edge.method], "paths": [edge.path], "ports": [edge.port]}}],
	"when": [
		{"key": "request.auth.claims[iss]", "values": [edge.issuer]},
		{"key": "request.auth.claims[sub]", "values": [edge.subject]},
		{"key": "request.auth.claims[aud]", "values": [edge.audience]},
		{"key": "request.auth.claims[model_id]", "values": [edge.model_id]},
		{"key": "request.auth.claims[tool_scopes]", "values": [edge.tool_scope]},
		{"key": "request.auth.claims[delegator_sub]", "values": [edge.delegator_sub]},
	],
}

tool_selector(tool) := {"matchLabels": {"aegismesh.io/workload": tool}}

tool_authentication_matches(policy, edge) if {
	policy.kind == "RequestAuthentication"
	policy.metadata.namespace == edge.namespace
	policy.metadata.name == edge.tool
	policy.spec == {
		"selector": tool_selector(edge.tool),
		"jwtRules": [{"issuer": edge.issuer, "jwksUri": edge.jwksURI, "audiences": [edge.audience]}],
	}
}

valid_tool_authorization(edge) if {
	some policy in input.kubernetes
	policy.kind == "AuthorizationPolicy"
	policy.metadata.namespace == edge.namespace
	policy.metadata.name == edge.tool
	policy.spec.selector == tool_selector(edge.tool)
	policy.spec.action == "ALLOW"
	expected := {tool_rule(other) |
		some other in input.toolAuthorizations
		other.namespace == edge.namespace
		other.tool == edge.tool
	}
	{rule | some rule in policy.spec.rules} == expected
	some authentication in input.kubernetes
	tool_authentication_matches(authentication, edge)
}

deny contains msg if {
	some edge in input.toolAuthorizations
	not valid_tool_authorization(edge)
	msg := sprintf("tool authorization drift: %s/%s", [edge.namespace, edge.tool])
}

deny contains msg if {
	some policy in input.kubernetes
	policy.kind == "RequestAuthentication"
	some authorization in input.kubernetes
	authorization.kind == "AuthorizationPolicy"
	authorization.metadata == policy.metadata
	some rule in authorization.spec.rules
	not tool_rule_declared(policy, rule)
	msg := sprintf("undeclared tool authorization: %s/%s", [policy.metadata.namespace, policy.metadata.name])
}

tool_rule_declared(authentication, rule) if {
	some edge in input.toolAuthorizations
	tool_authentication_matches(authentication, edge)
	tool_rule(edge) == rule
}

deny contains msg if {
	some profile in [input.kubernetes, input.ciliumHTTP]
	some route in profile
	route.kind == "HTTPRoute"
	some rule in route.spec.rules
	some backend in rule.backendRefs
	namespace := object.get(backend, "namespace", route.metadata.namespace)
	namespace != route.metadata.namespace
	not reference_granted(profile, route.metadata.namespace, namespace, backend)
	msg := sprintf("missing route grant: %s/%s -> %s/%s", [route.metadata.namespace, route.metadata.name, namespace, backend.name])
}

reference_granted(profile, from, to, backend) if {
	object.get(backend, "group", "") == ""
	object.get(backend, "kind", "Service") == "Service"
	some grant in profile
	grant.kind == "ReferenceGrant"
	grant.metadata.namespace == to
	grant.spec.from == [{"group": "gateway.networking.k8s.io", "kind": "HTTPRoute", "namespace": from}]
	grant.spec.to == [{"group": "", "kind": "Service", "name": backend.name}]
}

deny contains msg if {
	some grant in policies
	grant.kind == "ReferenceGrant"
	not scoped_reference_grant(grant)
	msg := sprintf("unscoped ReferenceGrant: %s/%s", [grant.metadata.namespace, grant.metadata.name])
}

scoped_reference_grant(grant) if {
	[from] := grant.spec.from
	[to] := grant.spec.to
	from == {"group": "gateway.networking.k8s.io", "kind": "HTTPRoute", "namespace": from.namespace}
	to == {"group": "", "kind": "Service", "name": to.name}
	from.namespace != grant.metadata.namespace
	regex.match("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", from.namespace)
	regex.match("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", to.name)
}

deny contains msg if {
	some route in policies
	route.kind == "HTTPRoute"
	not scoped_route(route.spec)
	msg := sprintf("unscoped HTTPRoute: %s/%s", [route.metadata.namespace, route.metadata.name])
}

scoped_route(spec) if {
	[parent] := spec.parentRefs
	parent.name != ""
	parent.sectionName != ""
	object.get(parent, "group", "gateway.networking.k8s.io") == "gateway.networking.k8s.io"
	object.get(parent, "kind", "Gateway") == "Gateway"
	[hostname] := spec.hostnames
	regex.match("^[a-z0-9-]+(\\.[a-z0-9-]+)+$", hostname)
	[rule] := spec.rules
	[match] := rule.matches
	match.method in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
	match.path.type == "Exact"
	regex.match("^(/[A-Za-z0-9._~-]+)*/?$", match.path.value)
	[backend] := rule.backendRefs
	object.get(backend, "group", "") == ""
	object.get(backend, "kind", "Service") == "Service"
	regex.match("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", backend.name)
	is_number(backend.port)
	backend.port >= 1
	backend.port <= 65535
	object.get(rule, "filters", []) == []
	object.get(backend, "filters", []) == []
}

# The Wave 6 data file is the reviewed compilation. Compare all profiles so
# adding an alternate path around any of the generated policies also fails.
deny contains "Wave 6 policy data is required" if {
	wave6_artifacts
	not wave6_policy_data_present
}

wave6_policy_data_present if is_object(data.aegismesh_wave6)

wave6_artifacts if input.wave6 == true

wave6_artifacts if {
	some policy in policies
	policy.kind == "ValidatingPolicy"
}

wave6_artifacts if count(input.mcpAuthorizations) > 0

wave6_artifacts if {
	some kind, _ in input.terraform.resource
	startswith(kind, "google_")
}

deny contains msg if {
	is_object(data.aegismesh_wave6)
	some field in (object.keys(data.aegismesh_wave6) | object.keys(input))
	object.filter(data.aegismesh_wave6, [field]) != object.filter(input, [field])
	msg := sprintf("Wave 6 artifact drift: %s", [field])
}

reviewed_terraform_kinds := {
	"aws_iam_role", "aws_iam_role_policy", "google_project_iam_binding",
	"google_access_context_manager_service_perimeter",
}

# The gateway authenticates both identities, checks canonical request routing
# and supplies verified, single-use approvals bound to this exact request.
default allow_mcp := false

mcp_edges contains edge if {
	some edge in data.aegismesh_wave6.mcpAuthorizations
	input.peer_spiffe_id == edge.principal
	input.gateway_spiffe_id == edge.gateway
	input.upstream == edge.upstream
	input.method == edge.method
	input.path == edge.path
}

allow_mcp if {
	some edge in mcp_edges
	edge.mode == "read-only"
	edge.method in {"GET", "HEAD"}
}

allow_mcp if {
	some edge in mcp_edges
	edge.mode == "approval-gated"
	is_string(input.request_id)
	input.request_id != ""
	regex.match("^[a-f0-9]{64}$", input.request_digest)
	input.verified_approval == {
		"request_id": input.request_id,
		"request_digest": input.request_digest,
		"principal": edge.principal,
		"gateway": edge.gateway,
		"upstream": edge.upstream,
		"method": edge.method,
		"path": edge.path,
	}
}

gcp_role_services := {
	"roles/storage.objectViewer": "storage.googleapis.com",
	"roles/artifactregistry.reader": "artifactregistry.googleapis.com",
}

deny contains msg if {
	some name, binding in input.terraform.resource.google_project_iam_binding
	not scoped_gcp_binding(binding)
	msg := sprintf("unscoped GCP IAM binding: %s", [name])
}

scoped_gcp_binding(binding) if {
	object.keys(binding) == {"project", "role", "members"}
	regex.match("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", binding.project)
	service := gcp_role_services[binding.role]
	is_array(binding.members)
	count(binding.members) > 0
	every member in binding.members {
		gcp_member_protected(member, binding.project, service)
	}
}

gcp_member_protected(member, project, service) if {
	pattern := concat("", [
		"^principal://iam[.]googleapis[.]com/projects/([1-9][0-9]{0,19})/locations/global/workloadIdentityPools/",
		project, "[.]svc[.]id[.]goog/subject/ns/[a-z0-9-]+/sa/[a-z0-9-]+$",
	])
	[[_, number]] := regex.find_all_string_submatch_n(pattern, member, 1)
	some name, perimeter in input.terraform.resource.google_access_context_manager_service_perimeter
	scoped_gcp_perimeter(name, perimeter)
	sprintf("projects/%s", [number]) in perimeter.status.resources
	service in perimeter.status.restricted_services
}

deny contains msg if {
	some name, perimeter in input.terraform.resource.google_access_context_manager_service_perimeter
	not scoped_gcp_perimeter(name, perimeter)
	msg := sprintf("unscoped GCP service perimeter: %s", [name])
}

scoped_gcp_perimeter(name, perimeter) if {
	object.keys(perimeter) == {"parent", "name", "title", "perimeter_type", "status"}
	regex.match("^[a-z][a-z0-9_]{0,49}$", name)
	regex.match("^accessPolicies/[1-9][0-9]{0,19}$", perimeter.parent)
	perimeter.name == sprintf("%s/servicePerimeters/%s", [perimeter.parent, name])
	perimeter.title == name
	perimeter.perimeter_type == "PERIMETER_TYPE_REGULAR"
	object.keys(perimeter.status) == {"resources", "restricted_services"}
	is_array(perimeter.status.resources)
	count(perimeter.status.resources) > 0
	every resource in perimeter.status.resources {
		regex.match("^projects/[1-9][0-9]{0,19}$", resource)
	}
	is_array(perimeter.status.restricted_services)
	count(perimeter.status.restricted_services) > 0
	every service in perimeter.status.restricted_services {
		service in gcp_role_services
	}
}
