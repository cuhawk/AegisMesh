# Benchmark results

go1.24.13, linux/amd64, GOMAXPROCS=3. 50 timed runs per row after three warm-ups.
Compile includes proof and in-memory rendering. Allocation is mean Go heap allocation per run.

| Workload nodes | Operation | p50 (ms) | p95 (ms) | p99 (ms) | Allocated (MiB/run) |
| ---: | --- | ---: | ---: | ---: | ---: |
| 50 | Proof | 0.105546 | 0.199414 | 0.340894 | 0.045964 |
| 50 | Compile | 0.643531 | 1.275224 | 1.386750 | 0.860548 |
| 250 | Proof | 0.705744 | 1.213114 | 3.273509 | 0.567725 |
| 250 | Compile | 4.156265 | 4.786547 | 5.650759 | 4.713626 |
| 1000 | Proof | 5.908786 | 9.645089 | 32.725776 | 5.153582 |
| 1000 | Compile | 19.321877 | 27.236483 | 29.740941 | 21.646530 |
