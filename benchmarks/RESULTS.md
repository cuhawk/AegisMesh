# Benchmark results

go1.24.10, linux/amd64, GOMAXPROCS=3. 50 timed runs per row after three warm-ups.
Compile includes proof and in-memory rendering. Allocation is mean Go heap allocation per run.

| Workload nodes | Operation | p50 (ms) | p95 (ms) | p99 (ms) | Allocated (MiB/run) |
| ---: | --- | ---: | ---: | ---: | ---: |
| 50 | Proof | 0.173852 | 0.408599 | 0.501417 | 0.045964 |
| 50 | Compile | 0.869115 | 2.452240 | 3.410658 | 0.858527 |
| 250 | Proof | 1.012448 | 2.282170 | 7.014893 | 0.569139 |
| 250 | Compile | 6.152328 | 12.108003 | 13.308212 | 4.714334 |
| 1000 | Proof | 8.732980 | 10.653241 | 17.582233 | 5.159207 |
| 1000 | Compile | 29.794564 | 43.544798 | 75.314813 | 21.645773 |
