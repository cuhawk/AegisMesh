# CODEX_SPEC: AegisMesh — Zero-Trust Intent-to-Cilium/SPIFFE/Terraform Compiler & Formal Reachability Prover

Build a rigorous multi-layer Zero-Trust policy compiler + formal graph prover in Go (`go 1.22+`) + Python test harness (`NO fake Kubernetes cluster claims — real verifiable policy compilation, YAML/HCL schema validation, and deterministic graph reachability proofs`).

## Required Architecture & Non-Trivial Invariants
1. **Declarative Service & Agent Topology Intent (`schemas/` + `examples/`):**
   - Models multi-tenant services AND AI agent workloads facing Simon Willison's "Lethal Trifecta" (private data access + untrusted content + network egress): pods/workloads, trust domains (`spiffe://...`), secret vaults, metadata endpoints (`169.254.169.254`), allowed FQDN APIs, IAM roles, and explicit deny invariants (`neverReach`).
2. **Multi-Target Compiler (`cmd/aegismesh`, `internal/compiler/`):**
   - Emits deterministic, schema-valid outputs:
     - **Cilium `CiliumNetworkPolicy` & `CiliumClusterwideNetworkPolicy` YAML:** default-deny ingress/egress, strict L7 HTTP `method`/`path` allowlists, `toFQDNs` DNS-proxy rules, and explicit block against cloud metadata CIDRs (`169.254.169.254/32`, `fd00:ec2::254/128`) and RFC1918 lateral movement.
     - **SPIFFE / SPIRE Workload Registration & Istio `AuthorizationPolicy` YAML:** short-lived SVID TTL (`<= 3600s`), strict principal matching (`cluster.local/ns/.../sa/...`), `STRICT` mTLS `PeerAuthentication`.
     - **Terraform / OpenTofu Least-Privilege IAM + OPA Rego Gate (`internal/terraform/`):** Generates scoped IAM policy JSON + `.tf` diff replacing wildcards (`s3:*`, `*` resources) with exact resource ARNs + condition keys, plus OPA/Rego CI bundle enforcing baseline invariants.
3. **Formal Reachability & Confused-Deputy Graph Prover (`internal/prover/`):**
   - Builds the effective directed capability graph `(Workload Identity, Network L3/L4/L7 Edges, DNS Rules, Redirect/Proxy Edges, IAM AssumeRole/PassRole Edges)` AFTER applying default-deny + deny-precedence semantics.
   - Proves or refutes security properties via shortest-path / BFS + counterexample witness path printing:
     - **Exfiltration invariant:** untrusted-input agent cannot reach raw internet or unauthorized egress FQDN while holding secret-vault capability.
     - **Metadata SSRF invariant:** zero path from web/agent ingress to `169.254.169.254`.
     - **Rule-shadowing & Precedence audit:** flags contradictory/overly-broad allow rules and wildcard CIDR/IAM regressions.
     - **Topology Drift Checker:** diffs compiled intent vs live exported cluster state JSON and emits remediation plan.
4. **Adversarial Mutation & Benchmark Suite (`internal/prover/prover_test.go`, `benchmarks/run_bench.go`):**
   - Automated mutation testing over `25+` hostile policy mutations (wildcard DNS `*.amazonaws.com`, HTTP redirect bypass to metadata IP, shadowed `allow all`, missing SVID condition, `iam:PassRole *`, permissive egress from quarantined reader) -> **100% caught** with exact counterexample trace.
   - `15+` valid complex production topologies -> **0% false rejections**.
   - Measure exact compile latency (`ms`) and graph-proof scalability across `50`, `250`, `1,000` microservice nodes (`p50/p95/p99` ms, memory MB) and save exact observed output to `benchmarks/RESULTS.md`.
5. **Docs & CI:**
   - `.github/workflows/ci.yml`: `go test -race -v ./...`, Rego syntax check / validation, and benchmark execution.
   - `rfcs/001-policy-compiler-and-prover.md` + `README.md` with clear architecture & honest scope (policy compilation + graph verification, not fake kernel hooking).
   - **CRITICAL:** Run `git rm CODEX_SPEC.md` before finishing!
