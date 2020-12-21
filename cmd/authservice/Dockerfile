ARG DOCKER_ARCH
FROM ${DOCKER_ARCH:-amd64}/alpine

ARG TAG
ARG GOARCH

ENV GOARCH ${GOARCH}

EXPOSE 8000
WORKDIR /app

VOLUME /root/.local/share/storj/authservice

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s \
  CMD ["/app/authservice", "--log.level=error", "health-check"]

COPY release/${TAG}/authservice_linux_${GOARCH:-amd64} /app/authservice
COPY cmd/authservice/entrypoint /entrypoint

ENTRYPOINT ["/entrypoint"]

ENV STORJ_CONFIG_DIR=/root/.local/share/storj/authservice
ENV STORJ_LISTEN_ADDR=0.0.0.0:8000
