// run_bench measures in-memory compilation and reachability on sparse meshes.
package main

import (
	"fmt"
	"math"
	"runtime"
	"slices"
	"time"

	"github.com/cuhawk/AegisMesh/internal/compiler"
	"github.com/cuhawk/AegisMesh/internal/intent"
	"github.com/cuhawk/AegisMesh/internal/prover"
)

const runs = 50

func topology(n int) intent.Intent {
	in := intent.Intent{
		TrustDomain: "cluster.local",
		SPIREParent: "spiffe://cluster.local/spire/agent/benchmark",
		Resources:   []intent.Resource{{ID: "metadata", Kind: "metadata", Value: "169.254.169.254"}},
	}
	for i := range n {
		id := fmt.Sprintf("service-%04d", i)
		next := fmt.Sprintf("service-%04d", (i+1)%n)
		in.Workloads = append(in.Workloads, intent.Workload{
			ID: id, Namespace: "benchmark", ServiceAccount: id, Tenant: "benchmark",
			SVIDTTL: 900, Ingress: i%50 == 0, Untrusted: i%100 == 0,
		})
		in.Rules = append(in.Rules, intent.Rule{
			Pair: intent.Pair{From: id, To: next}, Kind: "http", Port: 8080, Method: "GET", Path: "/status",
		})
		if i%50 == 0 {
			in.NeverReach = append(in.NeverReach, intent.Pair{From: id, To: "metadata"})
		}
	}
	return in
}

func measure(f func()) (p50, p95, p99, mib float64) {
	for range 3 {
		f()
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	latencies := make([]float64, 0, runs)
	for range runs {
		start := time.Now()
		f()
		latencies = append(latencies, float64(time.Since(start))/float64(time.Millisecond))
	}
	runtime.ReadMemStats(&after)
	slices.Sort(latencies)
	percentile := func(p float64) float64 { return latencies[int(math.Ceil(p*runs))-1] }
	return percentile(.50), percentile(.95), percentile(.99), float64(after.TotalAlloc-before.TotalAlloc) / runs / (1024 * 1024)
}

func main() {
	fmt.Println("# Benchmark results")
	fmt.Println()
	fmt.Printf("%s, %s/%s, GOMAXPROCS=%d. %d timed runs per row after three warm-ups.\n", runtime.Version(), runtime.GOOS, runtime.GOARCH, runtime.GOMAXPROCS(0), runs)
	fmt.Println("Compile includes proof and in-memory rendering. Allocation is mean Go heap allocation per run.")
	fmt.Println()
	fmt.Println("| Workload nodes | Operation | p50 (ms) | p95 (ms) | p99 (ms) | Allocated (MiB/run) |")
	fmt.Println("| ---: | --- | ---: | ---: | ---: | ---: |")
	for _, n := range []int{50, 250, 1000} {
		in := topology(n)
		for _, op := range []struct {
			name string
			run  func()
		}{
			{"Proof", func() {
				if err := prover.RequireSafe(in); err != nil {
					panic(err)
				}
			}},
			{"Compile", func() {
				if _, err := compiler.Compile(in); err != nil {
					panic(err)
				}
			}},
		} {
			p50, p95, p99, mib := measure(op.run)
			fmt.Printf("| %d | %s | %.6f | %.6f | %.6f | %.6f |\n", n, op.name, p50, p95, p99, mib)
		}
	}
}
