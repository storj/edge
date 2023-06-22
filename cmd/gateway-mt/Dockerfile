ARG GO_VERSION
FROM golang:${GO_VERSION}-alpine3.16 as builder

ADD . /gateway-mt
WORKDIR /gateway-mt

RUN apk update
RUN apk add --no-cache git gcc musl-dev
RUN go build -v -o /tmp/gateway-mt ./cmd/gateway-mt

FROM alpine:3.16

EXPOSE 20010
WORKDIR /app

COPY --from=builder /tmp/gateway-mt /app/gateway-mt

RUN apk add --no-cache libc6-compat
RUN apk add --no-cache gcompat

COPY cmd/gateway-mt/etc/nsswitch.conf /etc/nsswitch.conf
COPY cmd/gateway-mt/entrypoint /entrypoint

RUN chmod +x /app/gateway-mt

ENTRYPOINT ["/entrypoint"]

ENV STORJ_CONFIG_DIR=/root/.local/share/storj/gateway-mt
ENV STORJ_SERVER_ADDRESS=0.0.0.0:20010

# Healthcheck URL: http://<host>:20010/-/health
