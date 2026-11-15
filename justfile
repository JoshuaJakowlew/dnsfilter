# End-to-end benchmark of dnsfilter, see benchmark/README.md.
# Recipes run in benchmark/; settings: benchmark/config/bench.env.

set working-directory := "benchmark"

compose := "docker compose --env-file config/bench.env"

export BENCH_USER := `id -u` + ":" + `id -g`
export BENCH_COMMIT := `git describe --always --dirty 2> /dev/null || echo unknown`

# Run all scenarios and ramps, the report goes to results/latest
bench:
    #!/usr/bin/env bash
    mkdir -p data results
    trap '{{ compose }} down' EXIT
    {{ compose }} build --quiet && {{ compose }} run --rm loadgen

# Profile dnsfilter with perf under dnsperf load, the report goes to results/latest-profile
profile scenario="pass" outstanding="32":
    #!/usr/bin/env bash
    mkdir -p data results
    export CARGO_PROFILE=profiling
    trap '{{ compose }} down' EXIT
    {{ compose }} build --quiet && {{ compose }} run --rm profile {{ scenario }} {{ outstanding }}

# Stop and remove the benchmark containers
down:
    {{ compose }} down

clean: down
    rm -rf data results
