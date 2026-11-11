FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        dnsperf knot-dnsutils gawk gnuplot-nox fonts-dejavu-core bsdextrautils \
 && rm -rf /var/lib/apt/lists/*
