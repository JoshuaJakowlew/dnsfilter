#!/usr/bin/env bash
# Runs inside the loadgen container.
#   bench.sh data  generate the blocklist and query files into /data
#   bench.sh run   run the matrix and the ramps, write the report into /results/<date>
#   bench.sh profile <scenario> <outstanding>
#                  profile dnsfilter under dnsperf load, write the report into /results/profile-<date>
set -euo pipefail

generate_data() {
    # Blocked queries ask for a subdomain of a list entry, passed queries miss on every suffix.
    gawk -v n="$FILTER_SIZE" 'BEGIN { for (i = 0; i < n; i++) printf "ads-%d.block.test\n", i }' \
        > /data/blocklist.txt
    gawk -v n="$QUERY_COUNT" 'BEGIN { for (i = 0; i < n; i++) printf "www.site-%d.pass.test A\n", i }' \
        > /data/pass.txt
    gawk -v n="$QUERY_COUNT" -v m="$FILTER_SIZE" 'BEGIN {
        srand(42); for (i = 0; i < n; i++) printf "www.ads-%d.block.test A\n", int(rand() * m)
    }' > /data/block.txt
    gawk -v n="$QUERY_COUNT" -v m="$FILTER_SIZE" -v r="$BLOCK_RATIO" 'BEGIN {
        srand(43)
        for (i = 0; i < n; i++)
            if (rand() * 100 < r) printf "www.ads-%d.block.test A\n", int(rand() * m)
            else printf "www.site-%d.pass.test A\n", i
    }' > /data/mixed.txt
}

answer() {
    { kdig @127.0.0.1 -p "$1" +timeout=1 +retry=0 "$2" A 2> /dev/null || true; } \
        | gawk '/status:/ { s = $6 } $4 == "A" { a = $5 } END { sub(/;/, "", s); print (a != "" ? a : s) }'
}

check() {
    local port name want got status=0
    for _ in $(seq 50); do
        [[ $(answer "$FILTER_PORT" www.site-0.pass.test) == 192.0.2.1 ]] && break
        sleep 0.2
    done
    while read -r port name want; do
        got=$(answer "$port" "$name")
        printf '%-4s %-5s %-22s %s\n' "$([[ $got == "$want" ]] && echo ok || echo FAIL)" "$port" "$name" "${got:-no answer}"
        [[ $got == "$want" ]] || status=1
    done <<< "$UPSTREAM_PORT www.site-0.pass.test 192.0.2.1
$UPSTREAM_PORT www.ads-0.block.test NXDOMAIN
$FILTER_PORT www.site-0.pass.test 192.0.2.1
$FILTER_PORT ads-0.block.test 0.0.0.0
$FILTER_PORT www.ads-0.block.test 0.0.0.0"
    return $status
}

target() {
    case $1 in
        baseline) echo "$UPSTREAM_PORT /data/pass.txt" ;;
        *)        echo "$FILTER_PORT /data/$1.txt" ;;
    esac
}

run_matrix() {
    local port queries out
    echo "scenario,outstanding,repeat,sent,completed,lost,qps,avg_us,p50_us,p90_us,p99_us,p999_us,max_us,rcodes,valid" \
        > "$dir/runs.csv"
    for repeat in $(seq "$REPEATS"); do
        for outstanding in $OUTSTANDING; do
            for scenario in $SCENARIOS; do
                read -r port queries <<< "$(target "$scenario")"
                out="$dir/raw/$scenario-q$outstanding-r$repeat.txt"
                dnsperf=(dnsperf -s 127.0.0.1 -p "$port" -d "$queries" -q "$outstanding" -c "$CLIENTS" -t "$TIMEOUT")
                "${dnsperf[@]}" -l "$WARMUP" > /dev/null 2>&1
                "${dnsperf[@]}" -l "$DURATION" -O latency-histogram -O suppress=timeout > "$out" 2>&1
                gawk -v scenario="$scenario" -v outstanding="$outstanding" -v repeat="$repeat" \
                    -f /scripts/dnsperf.awk "$out" | tee -a "$dir/runs.csv"
            done
        done
    done
}

summarize() {
    gawk -F, '
        NR == 1 { next }
        {
            key = $1 "," $2
            if (!(key in runs)) order[++keys] = key
            runs[key]++; qps[key] += $7; qps2[key] += $7 * $7
            for (c = 8; c <= 12; c++) lat[key, c] += $c
            if ($13 > max[key]) max[key] = $13
            lost[key] += $6; invalid[key] += ($15 != "yes")
        }
        END {
            print "scenario,outstanding,runs,qps,qps_sd,avg_us,p50_us,p90_us,p99_us,p999_us,max_us,lost,invalid"
            for (i = 1; i <= keys; i++) {
                k = order[i]; n = runs[k]; mean = qps[k] / n
                sd = qps2[k] / n - mean * mean
                printf "%s,%d,%.0f,%.0f", k, n, mean, (sd > 0 ? sqrt(sd) : 0)
                for (c = 8; c <= 12; c++) printf ",%.1f", lat[k, c] / n
                printf ",%s,%d,%d\n", max[k], lost[k], invalid[k]
            }
        }' "$dir/runs.csv" > "$dir/summary.csv"
}

run_ramps() {
    local port queries
    echo "scenario,max_qps,lost_at_max" > "$dir/ramp.csv"
    for scenario in $RAMP_SCENARIOS; do
        read -r port queries <<< "$(target "$scenario")"
        resperf -s 127.0.0.1 -p "$port" -d "$queries" -R -m "$RAMP_MAX_QPS" -r "$RAMP_TIME" \
            -C "$CLIENTS" -t "$TIMEOUT" -P "$dir/raw/ramp-$scenario.dat" > "$dir/raw/ramp-$scenario.txt" 2>&1
        gawk -v s="$scenario" '/Maximum throughput/ { q = $3 } /Lost at that point/ { l = $5 }
            END { printf "%s,%.0f,%s\n", s, q, l }' "$dir/raw/ramp-$scenario.txt" | tee -a "$dir/ramp.csv"
    done
}

write_meta() {
    {
        echo "date=$(date -Iseconds)"
        echo "commit=$BENCH_COMMIT"
        echo "cpu=$(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | xargs)"
        echo "kernel=$(uname -r)"
        echo "dnsperf=$(dnsperf -h 2>&1 | gawk '/^Version/ { print $2 }')"
        env | grep -E '^(FILTER_SIZE|QUERY_COUNT|BLOCK_RATIO|SCENARIOS|OUTSTANDING|REPEATS|DURATION|WARMUP|CLIENTS|TIMEOUT|RAMP_|PROFILE_|.*_CPUS)' | sort
    } > "$dir/meta.txt"
}

summarize_stat() {
    local queries qps
    queries=$(gawk '/Queries completed:/ { print $3 }' "$dir/dnsperf.txt")
    qps=$(gawk '/Queries per second:/ { print $4 }' "$dir/dnsperf.txt")
    gawk -F, -v queries="$queries" -v qps="$qps" '
        $1 ~ /^[0-9.]+$/ { v[$3] = $1 + 0 }
        END {
            per_query["instructions"] = "instructions/query"
            per_query["cycles"] = "cycles/query"
            per_query["branches"] = "branches/query"
            per_query["branch-misses"] = "branch misses/query"
            per_query["cache-references"] = "cache references/query"
            per_query["cache-misses"] = "cache misses/query"
            per_query["context-switches"] = "context switches/query"
            order = "instructions cycles branches branch-misses cache-references cache-misses context-switches"
            printf "queries: %.0f\nqps: %.0f\n", queries, qps
            if (v["cycles"] > 0) printf "ipc: %.2f\n", v["instructions"] / v["cycles"]
            n = split(order, events, " ")
            for (i = 1; i <= n; i++) {
                e = events[i]
                if (e in v && queries > 0)
                    printf "%s: " (e == "context-switches" ? "%.4f" : "%.2f") "\n", per_query[e], v[e] / queries
            }
            if (v["branches"] > 0)
                printf "branch miss ratio: %.2f%%\n", 100 * v["branch-misses"] / v["branches"]
            if (v["cache-references"] > 0)
                printf "cache miss ratio: %.2f%%\n", 100 * v["cache-misses"] / v["cache-references"]
        }' "$dir/stat.csv" > "$dir/stat.txt"
}

demangle() {
    c++filt | sed -E 's/\[[0-9a-f]{16}\]//g'
}

report() {
    perf report -i "$data" --stdio -q -g none --percent-limit 0.5 "$@" 2> /dev/null | demangle
}

profile() {
    local scenario=$1 outstanding=$2 port queries data=/tmp/perf.data
    read -r port queries <<< "$(target "$scenario")"
    dnsperf=(dnsperf -s 127.0.0.1 -p "$port" -d "$queries" -q "$outstanding" -c "$CLIENTS" -t "$TIMEOUT")
    "${dnsperf[@]}" -l "$WARMUP" > /dev/null 2>&1
    local pid
    pid=$(pgrep -x dnsfilter)
    # Counting and sampling are separate perf sessions and run side by side.
    perf stat -p "$pid" -x, -e task-clock,cycles,instructions,branches,branch-misses,\
cache-references,cache-misses,context-switches -o "$dir/stat.csv" &
    local stat_pid=$!
    perf record -q -o "$data" -F "$PROFILE_FREQ" --call-graph dwarf -p "$pid" \
        -- "${dnsperf[@]}" -l "$PROFILE_DURATION" -O suppress=timeout > "$dir/dnsperf.txt"
    kill -INT "$stat_pid" 2> /dev/null || true
    wait "$stat_pid" || true
    summarize_stat
    {
        echo "# Self time by object, [...] is the kernel and its modules"
        report --no-children --sort dso
        echo -e "\n# Self time by function, [k] kernel, [.] user space"
        report --no-children --sort dso,sym
        echo -e "\n# Total time of dnsfilter functions, with callees"
        report --children --sort sym | grep -E '\] <?dnsfilter::'
    } > "$dir/report.txt"
    # --kernel marks only vmlinux frames, module frames end in [module]
    local folded=/tmp/stacks.folded
    perf script -i "$data" -s /usr/lib/perf-core/scripts/python/stackcollapse.py -- --kernel 2> /dev/null \
        | demangle | sed -E 's/([^;])(\[[a-z0-9_]+\])(;| )/\1\2_[k]\3/g' > "$folded"
    flamegraph.pl --colors java --hash --width 1600 --title "dnsfilter: $scenario, $outstanding in flight" \
        --subtitle "$(grep -h 'Queries per second' "$dir/dnsperf.txt" | xargs)" \
        "$folded" > "$dir/flamegraph.svg"
    grep -q '[[:alnum:]]_\[k\]' "$folded" \
        || { echo "no kernel frames in the profile, perf lacks kernel access (see README)" >&2; return 1; }
    grep -q 'dnsfilter::main' "$folded" \
        || { echo "dnsfilter symbols are not resolved (see README)" >&2; return 1; }
    rm -f "$folded"
}

case ${1:-run} in
    data)
        generate_data
        exit 0
        ;;
    run)
        dir="/results/$(date +%Y%m%d-%H%M%S)"
        mkdir -p "$dir/raw"
        ln -sfn "$(basename "$dir")" /results/latest
        check
        write_meta
        run_matrix
        summarize
        [[ -z $RAMP_SCENARIOS ]] || run_ramps
        gnuplot -e "dir='$dir'; scenarios='$SCENARIOS'; ramps='$RAMP_SCENARIOS'" /scripts/plots.gp

        echo
        column -t -s, "$dir/summary.csv"
        echo
        echo "report: results/$(basename "$dir")"
        if gawk -F, 'NR > 1 && $15 != "yes" { bad = 1; print "INVALID: " $0 } END { exit !bad }' "$dir/runs.csv"; then
            exit 1
        fi
        ;;
    profile)
        dir="/results/profile-$(date +%Y%m%d-%H%M%S)"
        mkdir -p "$dir"
        ln -sfn "$(basename "$dir")" /results/latest-profile
        trap 'chown -hR --reference=/results "$dir" /results/latest-profile' EXIT
        check
        write_meta
        echo "scenario=$2 outstanding=$3" >> "$dir/meta.txt"
        profile "$2" "$3"

        echo
        cat "$dir/stat.txt"
        echo "report: results/$(basename "$dir")"
        ;;
esac
