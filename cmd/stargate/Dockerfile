ARG DOCKER_ARCH
FROM ${DOCKER_ARCH:-amd64}/alpine
ARG TAG
ARG GOARCH
ENV GOARCH ${GOARCH}
EXPOSE 7777
WORKDIR /app
VOLUME /root/.local/share/storj/stargate
COPY release/${TAG}/stargate_linux_${GOARCH:-amd64} /app/stargate
COPY entrypoint /entrypoint
ENTRYPOINT ["/entrypoint"]
ENV STORJ_CONFIG_DIR=/root/.local/share/storj/stargate
ENV STORJ_SERVER_ADDRESS=0.0.0.0:7777
