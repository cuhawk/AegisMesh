# Benchmark results

go1.24.13, linux/amd64, GOMAXPROCS=3. 50 timed runs per row after three warm-ups.
Compile includes proof and in-memory rendering. Allocation is mean Go heap allocation per run.

| Workload nodes | Operation | p50 (ms) | p95 (ms) | p99 (ms) | Allocated (MiB/run) |
| ---: | --- | ---: | ---: | ---: | ---: |
| 50 | Proof | 0.111258 | 0.235325 | 0.245430 | 0.045964 |
| 50 | Compile | 0.684633 | 1.306420 | 1.399695 | 0.857722 |
| 250 | Proof | 1.076273 | 3.034536 | 5.493545 | 0.565588 |
| 250 | Compile | 4.055666 | 5.159141 | 6.561466 | 4.708078 |
| 1000 | Proof | 6.017185 | 9.120454 | 13.959131 | 5.152234 |
| 1000 | Compile | 21.412983 | 32.854086 | 45.243122 | 21.642941 |
