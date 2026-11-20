# RFC 001 — Policy compiler and reachability prover

## Intent and trust boundaries

The input is strict JSON. Workload IDs and their namespace/service-account pairs are unique. A trust domain defines the SPIFFE URI authority and the Istio principal prefix. Each service or agent belongs to a tenant and declares its X.509 SVID TTL. An ingress or untrusted marker starts a security query at the workload. Network ingress permissions still require explicit HTTP grants, for example from an in-mesh ingress gateway declared as a workload.

Resources represent exact DNS names, AWS IAM roles, Secrets Manager secrets, S3 objects, metadata addresses, or symbolic external network destinations. Managed HTTP is same-tenant and scoped by exact method, canonical path and TCP port. Managed external egress is scoped by exact DNS name and TCP port. Exact Kubernetes service-account OIDC claims constrain role assumption. IAM role permissions declare individual secret or object reads. Pass-role grants are rejected because the intent has no enforceable receiver constraint. Proxy and redirect rules describe observed or planned application and external dependencies. Include intermediary workloads, external services and downstream trust transitions in the input inventory.

## Graph and proof

Let V contain all declared workload and resource IDs. A rule key consists of source, destination, kind and, where applicable, protocol-specific match fields. The default grants no edge. A matching deny overrides its allow. A shadowed allow is also an audit violation. For each remaining grant, the graph has an edge from its source capability to its destination. HTTP and DNS match fields distinguish grants before that projection. A projected path represents possible capability transfer, including work performed by a downstream deputy.

For each source with applicable queries, breadth-first search explores outgoing edges in destination-ID order. The traversal starts at the source, so each vertex is reachable from itself. When a vertex is first discovered, its recorded predecessor yields a shortest path in edge count. The visited set handles cycles. The search tests three properties.

1. Every declared `neverReach` destination is absent from its source's reachable set.
2. Neither supported metadata IP nor a declared CIDR containing it is reachable from an ingress or untrusted workload.
3. An untrusted workload cannot have both a path to a private secret or object and a path to unauthorized egress. Two shortest witnesses show the capabilities separately. Raw internet and external CIDRs are unauthorized. An exact FQDN edge may be declared an approved destination from a trusted workload. Approval applies to that edge. Downstream redirects and proxies remain in the graph.

The validation pass rejects invalid resource and rule forms, broad or wildcard grants, ambiguous identities, shared role binding slots, and contradictory rules. With Q queried sources, V vertices and E edges, traversal takes O(Q(V+E)) time in the worst case. A traversal uses O(V) working memory after indexing the graph. Adjacency sorting and witness materialization add their own costs. Compile includes validation and graph proof before artifact generation. A finding prevents publication.

## Enforcement profiles

Both Kubernetes profiles emit Cilium default-deny ingress and egress. The clusterwide policy selects managed pods by label and explicitly denies AWS metadata IPv4 and IPv6 and external RFC1918 destinations. Workload network rules select namespace and service-account identities for pod traffic, which Cilium evaluates separately from external CIDR selection. Each DNS allow provisions a CoreDNS proxy match and an exact `toFQDNs` rule at the declared port.

Native Cilium HTTP applies anchored method and literal-path expressions at a plaintext hop. For a mesh with Istio STRICT mTLS, use the Istio profile. It keeps Cilium port and identity constraints and places HTTP authorization in Istio after decryption. Denied ordinary network tuples are excluded from allowlists. The metadata and RFC1918 blocks are explicit Cilium deny rules. Namespace-level PeerAuthentication assumes the namespace is managed. The Istio authorization selector and Cilium clusterwide policy require the declared workload label, so workload admission and label ownership are part of the trust boundary.

SPIRE entries bind the namespace and service account to one workload identity under a provisioned trusted parent. Issuance, workload attestation and Istio SDS integration require a configured SPIRE deployment. For AWS trust, the compiler emits exact OIDC principal, audience and subject, uses the Terraform AWS account allowlist, and configures a one-hour role session. IAM statements name individual ARNs and require secure transport for data reads. Workload credential availability still depends on DNS grants for the intended AWS APIs, AWS resource policy, and the configured identity provider. The migration diff compares desired and supplied prior Terraform JSON without AWS access. Import existing resources or use their existing state, and use Terraform planning to review any other attachments before applying.

## Drift and verification boundary

Drift indexes the supplied Kubernetes export by API group, kind, namespace and name, compares policy spec and managed service-account annotations, and ignores server bookkeeping. A missing object yields a create action, a changed object yields its desired representation, and an unexpected overlapping policy yields a review action. The caller determines the inventory scope and completeness. Kubernetes additive policies and application routes can introduce capabilities outside the input. Include network, Cilium clusterwide and Istio policies that could select managed workloads, then review discrepancies before relying on the proof.

The release checks cover artifact generation, offline schema and provider validation, Rego decisions, graph proofs, and exported Kubernetes comparisons. The proof is conditional on the complete declared graph and effective policy ownership. It does not observe kernel flows, DNS answers, route changes, application behavior, live SPIRE entries or effective AWS permissions. An actual deployment additionally depends on trusted DNS and the mTLS, SPIRE, IAM and control-plane prerequisites above. The benchmark measures in-process verification and rendering on synthetic rings and does not measure dataplane latency.
