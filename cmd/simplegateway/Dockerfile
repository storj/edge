ARG DOCKER_ARCH
FROM ${DOCKER_ARCH:-amd64}/alpine

ARG TAG
ARG GOARCH

ENV GOARCH ${GOARCH}

WORKDIR /app

VOLUME /root/.local/share/storj/simplegateway

COPY release/${TAG}/simplegateway_linux_${GOARCH:-amd64} /app/simplegateway
COPY cmd/simplegateway/entrypoint /entrypoint

ENTRYPOINT ["/entrypoint"]

ENV STORJ_CONFIG_DIR=/root/.local/share/storj/simplegateway
