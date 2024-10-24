ARG DOCKER_ARCH
FROM ${DOCKER_ARCH:-amd64}/alpine

ARG TAG
ARG GOARCH

ENV GOARCH ${GOARCH}

WORKDIR /app

VOLUME /root/.local/share/storj/authservice

COPY release/${TAG}/authservice_linux_${GOARCH:-amd64} /app/authservice
COPY cmd/authservice/entrypoint /entrypoint

ENTRYPOINT ["/entrypoint"]

ENV STORJ_CONFIG_DIR=/root/.local/share/storj/authservice

# Healthcheck URLs:
#  * Startup successful: https://<host>:20000/v1/health/startup
#  * Able to hit DB: https://<host>:20000/v1/health/live
