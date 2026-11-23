// Copyright 2020-2026 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

// Package par runs loops over index ranges on all CPUs.
package par

import (
	"runtime"
	"sync"
)

// Range calls f(start, end) on disjoint sub-ranges covering [0, n), in
// parallel when n is at least 2·minChunk, and returns when all calls have
// returned. f must not write to memory shared between sub-ranges.
func Range(n, minChunk int, f func(start, end int)) {
	workers := runtime.GOMAXPROCS(0)
	if n < 2*minChunk || workers == 1 {
		if n > 0 {
			f(0, n)
		}
		return
	}
	if n/minChunk < workers {
		workers = n / minChunk
	}
	chunk := (n + workers - 1) / workers
	var wg sync.WaitGroup
	for start := 0; start < n; start += chunk {
		end := min(start+chunk, n)
		wg.Add(1)
		go func() {
			defer wg.Done()
			f(start, end)
		}()
	}
	wg.Wait()
}

// Workers is the number of sub-ranges Range would use at most.
func Workers() int { return runtime.GOMAXPROCS(0) }
