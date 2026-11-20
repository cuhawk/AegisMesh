# AegisMesh

AegisMesh compiles a multi-tenant workload intent into Cilium, Istio, Kubernetes Gateway API, SPIRE and AWS IAM policies. Its Go prover checks shortest capability paths for denied reachability, metadata SSRF and the Lethal Trifecta before emitting artifacts.

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
| `tool-authorization-data.json` | OPA data for scoped agent-to-tool edges, emitted when the intent authorizes tool calls. |

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

## Verification

```sh
go test -race -v ./...
go run ./benchmarks/run_bench.go
```

CI compiles both examples, checks manifests against pinned upstream CRD schemas, exercises the Rego gate with changed artifacts, validates Terraform and executes the benchmarks. See the [RFC](rfcs/001-policy-compiler-and-prover.md) and [measured results](benchmarks/RESULTS.md).

The Go race suite caught 61 of 61 non-compliant intent mutations with witness traces (100%) and accepted 24 of 24 production-style topology fixtures (0 false rejections). Python validation checked 43 manifests across the two examples, found witnesses for all 26 Rego artifact rejections, and observed 13 denied and 2 allowed OPA tool requests.

Measured on Go 1.24.13, linux/amd64, with `GOMAXPROCS=3` and 50 timed runs per operation. Compile includes proof. Allocations are mean Go heap MiB per run.

| Workload nodes | Proof p95 (ms) | Compile p95 (ms) | Proof allocated (MiB/run) | Compile allocated (MiB/run) |
| ---: | ---: | ---: | ---: | ---: |
| 50 | 0.195445 | 4.513747 | 0.064467 | 0.871911 |
| 250 | 1.498015 | 10.151518 | 0.721749 | 4.885222 |
| 1000 | 11.339587 | 34.144336 | 5.809623 | 22.410612 |
