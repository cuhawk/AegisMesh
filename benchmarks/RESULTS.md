# Benchmark results

go1.24.13, linux/amd64, GOMAXPROCS=3. 50 timed runs per row after three warm-ups.
Each topology includes a cross-namespace Gateway route, a federated JWT-SVID tool edge, a sparse service ring and an executable allowlist per workload.
Compile includes proof and in-memory rendering. Allocation is mean Go heap allocation per run.

| Workload nodes | Operation | p50 (ms) | p95 (ms) | p99 (ms) | Allocated (MiB/run) |
| ---: | --- | ---: | ---: | ---: | ---: |
| 50 | Proof | 0.187783 | 0.294643 | 0.561615 | 0.068609 |
| 50 | Compile | 0.716057 | 1.295400 | 1.485746 | 1.059845 |
| 250 | Proof | 1.306807 | 6.204288 | 8.735498 | 0.690912 |
| 250 | Compile | 5.814992 | 7.247498 | 8.624160 | 5.704768 |
| 1000 | Proof | 8.937838 | 12.102581 | 13.084068 | 5.680665 |
| 1000 | Compile | 25.636085 | 39.874526 | 49.806905 | 25.665724 |

## Regression results

The Go race suite caught 82 of 82 non-compliant intent mutations with witness traces (100%) and accepted 27 of 27 production-style topology fixtures (0 false rejections). Python checked 79 Kubernetes manifests across three examples, including two Tetragon policies, and verified six changed sections in the HTML and JSON revision reports. The artifact checks observed 44 Rego rejections with witnesses and 26 denied and four allowed OPA tool requests.
