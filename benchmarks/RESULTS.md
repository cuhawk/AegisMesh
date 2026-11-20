# Benchmark results

go1.24.13, linux/amd64, GOMAXPROCS=3. 50 timed runs per row after three warm-ups.
Compile includes proof and in-memory rendering. Allocation is mean Go heap allocation per run.

| Workload nodes | Operation | p50 (ms) | p95 (ms) | p99 (ms) | Allocated (MiB/run) |
| ---: | --- | ---: | ---: | ---: | ---: |
| 50 | Proof | 0.107171 | 0.176707 | 0.315976 | 0.045639 |
| 50 | Compile | 0.537701 | 1.007529 | 1.135242 | 0.857393 |
| 250 | Proof | 0.708789 | 1.299650 | 1.937683 | 0.570446 |
| 250 | Compile | 4.331433 | 5.280620 | 7.628651 | 4.715526 |
| 1000 | Proof | 6.271659 | 14.278246 | 43.491747 | 5.169055 |
| 1000 | Compile | 22.778586 | 28.821982 | 36.895828 | 21.655539 |
