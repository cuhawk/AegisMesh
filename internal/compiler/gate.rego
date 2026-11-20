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
	count(rule.fromEndpoints[0].matchLabels) == 2
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

deny contains "invalid Terraform IAM configuration" if {
	not is_object(input.terraform.resource.aws_iam_role)
}

deny contains "invalid Terraform inline policies" if {
	not is_object(input.terraform.resource.aws_iam_role_policy)
}

deny contains msg if {
	some kind, _ in input.terraform.resource
	kind != "aws_iam_role"
	kind != "aws_iam_role_policy"
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
