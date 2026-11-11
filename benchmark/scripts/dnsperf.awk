# Turns `dnsperf -O latency-histogram` text output into one CSV row.
# Vars: scenario, outstanding, repeat. A run is valid when nothing was lost and every answer is NOERROR.

/Queries sent:/        { sent = $3 }
/Queries completed:/   { completed = $3 }
/Queries lost:/        { lost = $3 }
/Queries per second:/  { qps = $4 }
/Average Latency/      { avg = $4; max = $8; sub(/\)/, "", max) }
/Response codes:/      { rcodes = $0; sub(/.*codes: +/, "", rcodes); gsub(/ \([^)]*\),?/, "", rcodes) }
/^ +[0-9.]+ - [0-9.]+: +[0-9]+$/ {
    n++; upper[n] = $3; sub(/:/, "", upper[n]); count[n] = $4; total += $4
}

function us(seconds) { return sprintf("%.0f", seconds * 1e6) }

function percentile(p,    i, seen) {
    for (i = 1; i <= n; i++) {
        seen += count[i]
        if (seen >= p * total) return us(upper[i])
    }
    return ""
}

END {
    valid = (completed > 0 && lost == 0 && rcodes ~ /^NOERROR [0-9]+$/) ? "yes" : "no"
    printf "%s,%s,%s,%s,%s,%s,%.0f,%s,%s,%s,%s,%s,%s,%s,%s\n",
        scenario, outstanding, repeat, sent, completed, lost, qps,
        us(avg), percentile(0.5), percentile(0.9), percentile(0.99), percentile(0.999), us(max),
        rcodes, valid
}
