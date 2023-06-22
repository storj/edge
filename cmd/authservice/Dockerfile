ARG DOCKER_ARCH
ARG GO_VERSION
FROM ${DOCKER_ARCH:-amd64}/golang:${GO_VERSION}-alpine:3.16 as builder

ADD . /authservice
WORKDIR /authservice

RUN apk update
RUN apk add --no-cache git gcc musl-dev
RUN go build -v -o /tmp/authservice ./cmd/authservice

FROM ${DOCKER_ARCH:-amd64}/alpine

ENV GOARCH ${GOARCH}

EXPOSE 20000
WORKDIR /app

COPY --from=builder /tmp/authservice /app/authservice

COPY cmd/authservice/etc/nsswitch.conf /etc/nsswitch.conf
COPY cmd/authservice/entrypoint /entrypoint

ENTRYPOINT ["/entrypoint"]

ENV STORJ_CONFIG_DIR=/root/.local/share/storj/authservice
ENV STORJ_LISTEN_ADDR=0.0.0.0:20000

# Healthcheck URLs:
#  * Startup successful: https://<host>:20000/v1/health/startup
#  * Able to hit DB: https://<host>:20000/v1/health/live
