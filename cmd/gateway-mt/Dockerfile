ARG DOCKER_ARCH
FROM ${DOCKER_ARCH:-amd64}/alpine

ARG TAG
ARG GOARCH

ENV GOARCH ${GOARCH}

EXPOSE 20010
WORKDIR /app

VOLUME /root/.local/share/storj/gateway-mt

COPY cmd/gateway-mt/etc/nsswitch.conf /etc/nsswitch.conf
COPY release/${TAG}/gateway-mt_linux_${GOARCH:-amd64} /app/gateway-mt
COPY cmd/gateway-mt/entrypoint /entrypoint

ENTRYPOINT ["/entrypoint"]

ENV STORJ_CONFIG_DIR=/root/.local/share/storj/gateway-mt
ENV STORJ_SERVER_ADDRESS=0.0.0.0:20010

# Healthcheck URL: http://<host>:20010/-/health
