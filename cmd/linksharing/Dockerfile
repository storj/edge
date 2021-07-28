ARG DOCKER_ARCH
FROM ${DOCKER_ARCH:-amd64}/alpine
ARG TAG
ARG GOARCH
ENV GOARCH ${GOARCH}
EXPOSE 8080
WORKDIR /app
VOLUME /root/.local/share/storj/linksharing
COPY release/${TAG}/linksharing_linux_${GOARCH:-amd64} /app/linksharing
COPY pkg/linksharing/web/ /app/pkg/linksharing/web/
COPY cmd/linksharing/entrypoint /entrypoint
ENTRYPOINT ["/entrypoint"]
ENV STORJ_CONFIG_DIR=/root/.local/share/storj/linksharing

# Healthcheck URL:
# http://<host>:8080/health/process
