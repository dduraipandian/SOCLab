FROM debian:bookworm-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev make && rm -rf /var/lib/apt/lists/*
COPY hook/ /src/
RUN make -C /src

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        bash coreutils gawk curl cron sudo procps iproute2 python3 passwd ca-certificates \
    && rm -rf /var/lib/apt/lists/*
# Made-up users. priya.k and arun.m are sudoers; svc-maint reads /etc/shadow through group shadow.
RUN for u in priya.k arun.m meera.s svc-maint; do useradd -m -s /bin/bash "$u"; done \
    && usermod -aG shadow svc-maint \
    && printf 'priya.k ALL=(ALL) NOPASSWD: ALL\narun.m ALL=(ALL) NOPASSWD: ALL\n' > /etc/sudoers.d/lab \
    && chmod 440 /etc/sudoers.d/lab
COPY maint/nightly.sh /opt/maint/nightly.sh
COPY entrypoint.sh /entrypoint.sh
COPY sensor/ /opt/sensor/sensor/
COPY route_keeper.py /opt/route_keeper.py
COPY --from=build /src/libsensor.so /usr/lib/libsensor.so
# Last, so build steps above are not hooked.
RUN echo /usr/lib/libsensor.so > /etc/ld.so.preload
ENTRYPOINT ["/entrypoint.sh"]
