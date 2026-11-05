# Experimental kernel firewall proof, NOT the production live scanner.
# Alpine 3.24 from the existing nginx image; nginx itself is never started.
FROM nginx:stable-alpine@sha256:970364228b1e4f932abc22d321932816782cca8a20b85a77552a7cfe9acfb3b5
RUN apk add --no-cache nftables util-linux \
 && addgroup -S compliance -g 65532 \
 && adduser -S -D -H -u 65532 -G compliance compliance
COPY nftables.nft /etc/compliance-egress.nft
COPY entrypoint.sh /usr/local/bin/compliance-egress-start
COPY firewall_probe.sh /opt/compliance/firewall_probe.sh
RUN chmod 0555 /usr/local/bin/compliance-egress-start /opt/compliance/firewall_probe.sh \
 && chmod 0444 /etc/compliance-egress.nft
ENTRYPOINT ["/usr/local/bin/compliance-egress-start"]
CMD ["/bin/sh", "/opt/compliance/firewall_probe.sh"]
