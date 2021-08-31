#!/bin/bash -xe

cd /code
go install -v storj.io/gateway-mt/cmd/linksharing

linksharing run \
    --auth-service.base-url http://authservice:20000 \
    --auth-service.token super-secret \
    --address=:20020 \
    --public-url=http://localhost:20020 \
    --log.level=debug
