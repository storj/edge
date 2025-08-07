ARG DOCKER_ARCH
FROM ${DOCKER_ARCH:-amd64}/alpine

ARG TAG
ARG GOARCH

ENV GOARCH ${GOARCH}

WORKDIR /app

VOLUME /root/.local/share/storj/mcp-server

COPY release/${TAG}/mcp-server_linux_${GOARCH:-amd64} /app/mcp-server
COPY cmd/mcp-server/entrypoint /entrypoint

ENTRYPOINT ["/entrypoint"]

ENV STORJ_CONFIG_DIR=/root/.local/share/storj/mcp-server
