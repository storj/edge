#!/usr/bin/env bash

set -e

export PATH=$GOPATH/bin:$PATH

cd /code
go install -v storj.io/gateway-mt/cmd/gateway-mt

until uplink ls --access "$(storj-sim network env GATEWAY_0_ACCESS --config-dir /config/local-network 2>/dev/null)" &>/dev/null; do
    echo "access not ready, sleeping"
    sleep 3
done

access=$(storj-sim network env GATEWAY_0_ACCESS --config-dir /config/local-network)
echo "==================================================================="
echo "Access ${access}"
echo "==================================================================="
uplink access register "${access}" --auth-service http://authservice:8000
echo "==================================================================="

gateway-mt run --server.address="0.0.0.0:7777" --auth-token=super-secret --auth-url=http://authservice:8000 --domain-name=gateway.local
