# Vars (gnuplot -e): dir, scenarios, ramps.

set terminal pngcairo size 1100,650 font "DejaVu Sans,10" noenhanced
set grid
set key outside right top

set datafile separator comma
rows(s) = sprintf("< grep '^%s,' %s/summary.csv", s, dir)
set logscale x 2
set xlabel "queries in flight (dnsperf -q)"

set output dir."/throughput.png"
set title "Throughput, mean and standard deviation over repeats"
set ylabel "answered queries per second"
set yrange [0:*]
plot for [s in scenarios] rows(s) using 2:4:5 with yerrorlines lw 2 title s

set output dir."/latency.png"
set multiplot layout 1, 2
set logscale y
set yrange [*:*]
set ylabel "microseconds"
set title "p50 latency"
plot for [s in scenarios] rows(s) using 2:7 with linespoints lw 2 title s
set title "p99 latency"
plot for [s in scenarios] rows(s) using 2:9 with linespoints lw 2 title s
unset multiplot

if (strlen(ramps) > 0) {
    set output dir."/ramp.png"
    set datafile separator whitespace
    unset logscale
    set title "resperf ramp: answered rate against the target send rate"
    set xlabel "seconds"
    set ylabel "queries per second"
    set yrange [0:*]
    plot for [s in ramps] dir."/raw/ramp-".s.".dat" using 1:4 with lines lw 2 title s." answered", \
         for [s in ramps] dir."/raw/ramp-".s.".dat" using 1:2 with lines dt 2 lc "gray" title s." target"
}
