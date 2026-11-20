# AegisMesh

AegisMesh compiles a multi-tenant workload intent into Cilium, Istio, SPIRE and AWS IAM policies. Its Go prover checks shortest capability paths for denied reachability, metadata SSRF and the Lethal Trifecta before emitting artifacts.

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

The example expects CoreDNS labeled `k8s-app=kube-dns` in `kube-system` and uses regional AWS endpoints. An Istio installation must provision the matching trust domain, sidecar enrollment, SPIRE attestation and workload identity socket, and any required mesh control-plane connectivity. See the RFC for policy ownership and infrastructure assumptions.

For drift, pass a scope-filtered Kubernetes JSON `List` of the relevant Cilium, Kubernetes network, Istio and service-account objects. Include clusterwide policies that could select a managed workload.

```sh
go run ./cmd/aegismesh drift -intent examples/multitenant.json -live exported.json
```

Use `-profile cilium-http` for that manifest set. Drift prints a JSON remediation plan and exits with a nonzero status when it finds drift. The intent schema and example are in [schemas](schemas/) and [examples](examples/).

## Verification

```sh
go test -race -v ./...
go run ./benchmarks/run_bench.go
```

CI compiles the example, checks manifests against pinned upstream CRD schemas, exercises the Rego gate with changed artifacts, validates Terraform and executes the benchmarks. See the [RFC](rfcs/001-policy-compiler-and-prover.md) and [measured results](benchmarks/RESULTS.md).
