# Benchmark results

go1.24.13, linux/amd64, GOMAXPROCS=3. 50 timed runs per row after three warm-ups.
Each topology includes a cross-namespace Gateway route, a JWT-SVID tool edge and a sparse service ring.
Compile includes proof and in-memory rendering. Allocation is mean Go heap allocation per run.

| Workload nodes | Operation | p50 (ms) | p95 (ms) | p99 (ms) | Allocated (MiB/run) |
| ---: | --- | ---: | ---: | ---: | ---: |
| 50 | Proof | 0.134272 | 0.195445 | 0.357649 | 0.064467 |
| 50 | Compile | 0.658692 | 4.513747 | 7.596154 | 0.871911 |
| 250 | Proof | 0.785363 | 1.498015 | 2.278923 | 0.721749 |
| 250 | Compile | 4.059063 | 10.151518 | 12.580476 | 4.885222 |
| 1000 | Proof | 6.843335 | 11.339587 | 15.356677 | 5.809623 |
| 1000 | Compile | 19.184461 | 34.144336 | 43.082270 | 22.410612 |

## Regression results

The Go race suite caught 61 of 61 non-compliant intent mutations with witness traces (100%) and accepted 24 of 24 production-style topology fixtures (0 false rejections). Python validation checked 43 manifests across the two examples, found witnesses for all 26 Rego artifact rejections, and observed 13 denied and 2 allowed OPA tool requests.
