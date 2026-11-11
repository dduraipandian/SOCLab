FROM alpine:3.20
RUN apk add --no-cache iptables iproute2 bash
COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/bin/bash", "/entrypoint.sh"]
