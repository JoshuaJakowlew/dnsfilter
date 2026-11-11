FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        dnsperf knot-dnsutils gawk gnuplot-nox fonts-dejavu-core bsdextrautils linux-perf binutils \
 && rm -rf /var/lib/apt/lists/*
# Debian has no flame graph renderer, so take the script from Brendan Gregg's FlameGraph.
ADD --chmod=755 --checksum=sha256:088f82e6848a4f12a56e1e8e8170ee6761fccf12e5615cd64630f6b087c99ea7 \
    https://raw.githubusercontent.com/brendangregg/FlameGraph/41fee1f99f9276008b7cd112fca19dc3ea84ac32/flamegraph.pl \
    /usr/local/bin/flamegraph.pl
