# Image for the namespace integration tests on hosts that forbid
# unprivileged user namespaces. It carries the tools the stages drive (nft
# and FRR from the target distribution, a pinned Traefik) and nothing else;
# the statically linked test binary is mounted in at run time.
#
#   docker build -t testudo-netns:12 scripts/netns-image
#   git config testudo.netnsImage testudo-netns:12
FROM debian:12-slim
ARG TRAEFIK_VERSION=v3.3.4
RUN apt-get update \
 && apt-get install -y --no-install-recommends nftables iproute2 frr frr-pythontools procps ca-certificates curl keepalived conntrackd conntrack \
    kea-dhcp4-server kea-dhcp6-server unbound dns-root-data chrony radvd isc-dhcp-client bind9-dnsutils util-linux ppp pppoe dnsmasq-base dhcpcd-base snmpd snmp \
 && curl -fsSL "https://github.com/traefik/traefik/releases/download/${TRAEFIK_VERSION}/traefik_${TRAEFIK_VERSION}_linux_amd64.tar.gz" \
    | tar -xz -C /usr/local/bin traefik \
 && apt-get purge -y curl && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/*
