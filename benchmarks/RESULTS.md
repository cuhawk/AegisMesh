# Benchmark results

go1.24.13, linux/amd64, GOMAXPROCS=3. 50 timed runs per row after three warm-ups.
Each topology includes a cross-namespace Gateway route, a federated JWT-SVID tool edge, a sparse service ring, executable allowlists, a GCP IAM binding and perimeter, and an MCP gateway with hardened pod admission.
Compile includes proof and in-memory rendering. Allocation is mean Go heap allocation per run.

| Workload nodes | Operation | p50 (ms) | p95 (ms) | p99 (ms) | Allocated (MiB/run) |
| ---: | --- | ---: | ---: | ---: | ---: |
| 50 | Proof | 0.208542 | 0.327372 | 0.978876 | 0.080170 |
| 50 | Compile | 1.221893 | 2.003203 | 2.016731 | 1.124876 |
| 250 | Proof | 1.040760 | 1.623346 | 1.695750 | 0.740547 |
| 250 | Compile | 5.939803 | 7.097447 | 9.572866 | 5.887447 |
| 1000 | Proof | 9.211040 | 10.829638 | 11.473336 | 5.891579 |
| 1000 | Compile | 26.104696 | 38.236583 | 69.371913 | 26.299110 |

## Regression results

The Go race suite rejected 115 of 115 non-compliant intent mutations with witnesses and accepted 32 of 32 valid topology fixtures, with zero false rejections. Artifact validation checked 100 Kubernetes manifests across four examples and six changed sections in the Wave 4 revision report.

OPA rejected 66 artifact mutations with witnesses. The runtime checks observed 26 denied and four allowed tool requests, and 20 denied and two allowed MCP requests. The Kyverno CLI denied 15 non-compliant pods and accepted the compliant pod. Terraform validated the combined AWS and Google provider configuration.
