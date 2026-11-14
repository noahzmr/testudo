# Image for the namespace integration tests on hosts that forbid
# unprivileged user namespaces. It carries the tools the stages drive
# (nft from the target distribution) and nothing else; the statically linked
# test binary is mounted in at run time.
#
#   docker build -t testudo-netns:12 scripts/netns-image
#   git config testudo.netnsImage testudo-netns:12
FROM debian:12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends nftables iproute2 \
 && rm -rf /var/lib/apt/lists/*
