#!/bin/bash
STORJ_SRC_DIR=$HOME/storj/storj \
GATEWAY_SRC_DIR=$HOME/storj/gateway-mt \
docker-compose \
    up --detach
