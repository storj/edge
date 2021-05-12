#!/usr/bin/env bash

set -e

export PATH=$GOPATH/bin:$PATH

cd /code
go install -v storj.io/gateway-mt/cmd/authservice

until storj-sim network env --config-dir /config/local-network &>/dev/null; do
    echo "storj-sim not ready, sleeping"
    sleep 3
done

SATELLITE_ID="$(storj-sim network env SATELLITE_0_ID --config-dir /config/local-network)"
echo "Found satellite ID: $SATELLITE_ID"

authservice run --auth-token="super-secret" --allowed-satellites="${SATELLITE_ID}@" --endpoint="http://localhost:7777"
