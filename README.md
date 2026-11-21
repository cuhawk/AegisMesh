# AegisMesh

AegisMesh compiles a multi-tenant workload intent into Cilium, Istio, Kubernetes Gateway API, SPIRE, Tetragon, Kyverno, AWS IAM, and GCP IAM and VPC Service Controls policies. Its Go prover checks shortest capability paths for denied reachability, metadata SSRF and the Lethal Trifecta before emitting artifacts.

## Try it

Use Go 1.24 or later from the repository root.

```sh
go run ./cmd/aegismesh prove -intent examples/multitenant.json
go run ./cmd/aegismesh compile -intent examples/multitenant.json \
  -previous-tf examples/legacy-iam.tf.json -out ./compiled
opa eval --fail -d compiled/gate.rego -i compiled/bundle.json 'data.aegismesh.allow == true'
```

Compilation requires a new output directory. Configure workloads with the declared namespaces and service accounts and the pod label `aegismesh.io/workload=<id>`. Choose one Kubernetes manifest set per installation.

| Artifact | Contents |
| --- | --- |
| `kubernetes.yaml` | Cilium network isolation and DNS rules with Istio principal, HTTP and STRICT mTLS policy. This profile relies on Istio to inspect HTTP after TLS termination. |
| `cilium-http.yaml` | Cilium network isolation, DNS and native L7 HTTP on plaintext application hops. |
| `spire-entries.json` | Workload entries for `spire-server entry create -data`, with explicit attested parent identity and X.509 SVID TTL. |
| `iam.tf.json`, `iam-*.json` | Terraform/OpenTofu JSON configuration and exact IAM trust and access documents. Use the existing Terraform state or import roles and inline policies before planning a migration. |
| `iam.tf.json.diff` | Optional offline diff from `-previous-tf`. Sample changes replace an S3 wildcard grant with scoped object and secret reads. |
| `bundle.json`, `gate.rego` | Machine-readable compilation and OPA gate. |
| `tetragon.yaml` | Namespaced executable allowlists and the MCP agent socket guard. |
| `tool-authorization-data.json` | OPA data for scoped agent-to-tool edges, emitted when the intent authorizes tool calls. |
| `wave6-policy-data.json` | Reviewed Wave 6 compilation for the artifact gate and MCP runtime authorization. |

The example expects CoreDNS labeled `k8s-app=kube-dns` in `kube-system` and uses regional AWS endpoints. An Istio installation must provision the matching trust domain, sidecar enrollment, SPIRE attestation and workload identity socket, and any required mesh control-plane connectivity. See the RFC for policy ownership and infrastructure assumptions.

For drift, pass a scope-filtered Kubernetes JSON `List` of the relevant Cilium, Kubernetes network, Istio and service-account objects. Include clusterwide policies that could select a managed workload.

```sh
go run ./cmd/aegismesh drift -intent examples/multitenant.json -live exported.json
```

Use `-profile cilium-http` for that manifest set. Drift prints a JSON remediation plan and exits with a nonzero status when it finds drift. The intent schema and example are in [schemas](schemas/) and [examples](examples/).

## Wave 3 isolation

[The Wave 3 example](examples/wave3.json) includes a scoped tool call, a cross-namespace Gateway route and an inventory of existing isolation settings.

- Declare an agent's `svidClaims` with `model_id`, `tool_scopes` and `delegator_sub`. Set `toolScope` on the destination and the HTTP allow edge. Istio checks the mTLS principal, verified JWT issuer and SPIFFE subject, tool audience, model, scope and delegator. The prover reports a witness when a workload can reach a deputy that has an operation the workload cannot invoke directly. The Cilium-only profile denies claim-scoped tool calls.
- Configure `jwtAuthority` for a trusted JWT-SVID issuer that attests the declared model and delegation and signs the custom claims. The issuer must use strings for `model_id` and `delegator_sub`, a string array for `tool_scopes`, the agent SPIFFE ID as `sub` and the tool SPIFFE ID as `aud`. Provision Istio access to the JWKS. The generated SPIRE registration entries cover workload identity. Claim issuance is an integration requirement based on the custom-claims option in [spiffe/spiffe#383](https://github.com/spiffe/spiffe/issues/383).
- For OPA runtime enforcement, load `gate.rego` and `tool-authorization-data.json` and query `data.aegismesh.allow_tool`. The trusted caller supplies `namespace`, `tool`, `method`, `path`, `port` as a decimal string, `peer_principal` in Istio format, and `claims` from a JWT whose signature, issuer and lifetime it has verified. The query checks those claims against the authorized edge. Query `data.aegismesh.allow` separately for artifact validation.
- Declare each `httpRoutes` entry against a managed ingress workload and its existing Gateway listener. Provision that Gateway under the workload ID and configure its listener to accept the route namespace. Each route requires a matching HTTP edge and a Service whose declared port and endpoints lead to the backend workload. For a cross-namespace Service reference, declare a service-name-scoped `referenceGrants` entry in the Service namespace. Gateway API grants consent to HTTPRoutes in the source namespace, so restrict who can create routes there.
- Supply `isolation` inventory from the deployment configuration. Envoy admin listeners require an isolated loopback or Unix socket. Include TLS sync source and effective destination names so the prover can detect two distinct sources writing one Secret. List pod and service CIDRs with the `ipBlocks` to audit, including any exceptions. The inventory check runs before emission and deployment manages those settings. CRD validation uses Cilium 1.19.6 and Istio 1.31.4, which include fixes for the referenced upstream advisories. [Cilium Envoy admin socket](https://github.com/cilium/cilium/security/advisories/GHSA-3fcv-jvfp-m4q9) · [Cilium TLS secret sync](https://github.com/cilium/cilium/security/advisories/GHSA-xqhm-7xhv-6ppj) · [Cilium NetworkPolicy ipBlock](https://github.com/cilium/cilium/security/advisories/GHSA-fm8w-2m5w-9j7r) · [Istio waypoint and HBONE IP matching](https://github.com/istio/istio/security/advisories/GHSA-9gqj-583v-mpqp)

## Wave 4 federation and runtime policy

[The Wave 4 example](examples/wave4.json) uses two Kubernetes clusters with distinct SPIFFE trust domains. Each member of `federation.trustDomains` declares its cluster name, SPIRE parent identity, HTTPS bundle endpoint and the peer bundles it trusts. Workloads inherit the top-level trust domain unless they declare their own. Each cross-domain HTTP allow requires mutual bundle trust. The prover checks each reachable cross-domain workload pair against `federation.allowReach`, including paths through intermediaries, and reports the shortest unauthorized path. Existing tenant boundaries and `neverReach` constraints still apply.

Federated compilation writes deployment manifests and SPIRE entries under `clusters/<cluster>/`. Use each directory with its named cluster. The cluster names must match Cilium Cluster Mesh labels. Deploy the Istio profile for cross-domain HTTP. The Cilium-only profile limits HTTP enforcement to in-cluster edges without JWT claim requirements. Istio policy uses the exact source trust domain in each principal.

`spire-bundles.json` records the local endpoint and trusted peer endpoint map. Configure the matching SPIRE federation relationships, bootstrap the peer bundles according to the endpoint TLS profile, and configure the mesh to validate peer SVIDs while preserving their original domain. Istio trust-domain aliases can equate principals across domains and must be disabled for this profile.

Set `execAllowlist` to the workload's absolute executable paths, including required entrypoints and interpreters. Apply the generated `tetragon.yaml` with Tetragon 1.5, namespace and pod-label policy filtering, and a kernel with BPF LSM enabled. The policy selects the workload's labeled pods and denies resolved executable paths outside the allowlist using the `bprm_check_security` hook. The allowlist evaluates paths, so allowed executables must be protected against replacement.

Compare two compiled revisions offline or check a cluster's live objects.

```sh
go run ./cmd/aegismesh compile -intent examples/wave4.json -out ./compiled-wave4
go run ./cmd/aegismesh --diff ./compiled/bundle.json ./compiled-wave4/bundle.json -out ./policy-diff
go run ./cmd/aegismesh drift -intent examples/wave4.json -cluster west -live west-export.json
```

Open `policy-diff/index.html` for the side-by-side view or read `policy-diff/policy-diff.json` for the changed sections and their previous and current values. Include managed Tetragon policies in the live export when checking runtime drift.

## Wave 6 cloud, admission and MCP policy

[The Wave 6 example](examples/wave6.json) combines AWS IAM, GCP IAM and VPC Service Controls, hardened pod admission, and an MCP gateway.

- **GCP.** Declare the project ID and number, GKE workload bindings, and enforced service perimeters. Bindings grant the predefined Storage Object Viewer or Artifact Registry Reader role to exact Kubernetes service-account subjects in the target project's GKE workload identity pool. The perimeter must cover that project and restrict the service corresponding to the role. GCP project aliases can be used as `neverReach` targets. Provision the GKE workload identity pool and Access Context Manager access policy beforehand. Terraform bindings manage the full member set for each project and role, so reconcile existing members and import existing bindings and perimeters before applying. Restrict which clusters, namespaces and users can mint the declared Kubernetes identities.
- **Admission.** Set `admission.registryPrefixes` on each protected workload. The Kyverno ValidatingPolicy rejects pods with mismatched workload labels and service accounts, host namespaces, hostPath volumes, root users, writable root filesystems, privilege escalation, or images outside the listed prefixes. Prefixes end with a slash so similarly named registries or repositories cannot match. The policy also checks init and ephemeral containers, including the ephemeral-container update subresource. Use Kyverno 1.16 and configure any injected sidecars and init containers to meet the same policy.
- **MCP.** Declare an untrusted agent, a dedicated trusted gateway in the same tenant and trust domain, an exact upstream FQDN resource, and exact method/path grants. GET and HEAD can be read-only. Approval-gated grants require a verified approval even for GET or HEAD. The gateway alone gets Cilium DNS L7 and TCP 443 egress to the upstream. The agent can reach the gateway on TCP 8080 through the Istio profile, which enforces the caller principal and declared methods and paths. Tetragon constrains executables and blocks direct agent TCP connections to port 443 using the `security_socket_connect` kprobe. This guard requires a kernel that supports Tetragon's kprobe override in addition to the BPF LSM setting used for executable enforcement.

Provision the gateway implementation and its Service on port 8080. The gateway verifies mTLS, validates the host and exact request path, and queries `data.aegismesh.allow_mcp` with `peer_spiffe_id`, `gateway_spiffe_id`, `upstream`, `method`, and `path`. The gateway keeps forwarding to the configured HTTPS origin, verifies the server certificate, rejects redirects, and rejects ambiguous encodings and query strings. Use read-only methods only for operations the upstream actually treats as read-only. For gated calls, the trusted approval verifier must bind a short-lived, single-use approval to the request ID, SHA-256 digest of the exact forwarded request, principal, gateway, upstream, method and path. Pass `request_id`, `request_digest` and the corresponding `verified_approval` object to OPA, then consume the approval before forwarding. The OPA inputs must come from the gateway and approval verifier. This integration enforces HTTP and approval semantics above the encrypted transport.

Load `wave6-policy-data.json` from a trusted compilation when gating the bundle. The gate also checks the GCP binding and perimeter constraints. Deploy the Cilium-only profile for workloads that do not need MCP access. That profile leaves MCP agent-to-gateway connections closed.

```sh
go run ./cmd/aegismesh compile -intent examples/wave6.json \
  -previous-tf examples/legacy-iam.tf.json -out ./compiled-wave6
opa eval --fail -d compiled-wave6/gate.rego -d compiled-wave6/wave6-policy-data.json \
  -i compiled-wave6/bundle.json 'data.aegismesh.allow == true'
python tests/validate_artifacts.py ./compiled-wave6 --example wave6.json
```

## Verification

```sh
go test -race -v ./...
go run ./benchmarks/run_bench.go
```

CI compiles the checked-in examples, validates manifests against pinned CRD schemas, and runs Kyverno admission and OPA policy checks, drift and revision comparisons, Terraform validation, and benchmarks. See the [RFC](rfcs/001-policy-compiler-and-prover.md) and [measured results](benchmarks/RESULTS.md).

The Go race suite rejected 115 of 115 non-compliant intent mutations with witnesses and accepted 32 of 32 valid topology fixtures, with zero false rejections. Artifact validation checked 100 Kubernetes manifests across four examples. OPA rejected 66 artifact mutations with witnesses, denied 20 MCP requests and allowed two. The Kyverno CLI denied 15 non-compliant pods and accepted the compliant pod.

Measured on Go 1.24.13, linux/amd64, with `GOMAXPROCS=3` and 50 timed runs per operation. Compile includes proof. Allocations are mean Go heap MiB per run.

| Workload nodes | Proof p95 (ms) | Compile p95 (ms) | Proof allocated (MiB/run) | Compile allocated (MiB/run) |
| ---: | ---: | ---: | ---: | ---: |
| 50 | 0.327372 | 2.003203 | 0.080170 | 1.124876 |
| 250 | 1.623346 | 7.097447 | 0.740547 | 5.887447 |
| 1000 | 10.829638 | 38.236583 | 5.891579 | 26.299110 |
