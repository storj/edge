#!/usr/bin/env bash

set -e

export PATH=$GOPATH/bin:$PATH

cd /code
go install -v storj.io/gateway-mt/cmd/authservice

authservice run --auth-token "super-secret" --allowed-satellites="storjsim:10000" --endpoint="http://localhost:7777"
