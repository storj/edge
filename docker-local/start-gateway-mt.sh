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
keys=$(uplink access register "${access}" --auth-service http://authservice:8000)
access_key_id=$(echo "${keys}" | grep "Access Key ID" | rev | cut -d " " -f1 | rev)
secret_key_id=$(echo "${keys}" | grep "Secret Key" | rev | cut -d " " -f1 | rev)

if [ -z "$access_key_id" ]; then
    echo "Failed to get access_key_id"
    exit 1
fi
if [ -z "$secret_key_id" ]; then
    echo "Failed to get access_key_id"
    exit 1
fi
echo "==================================================================="
echo "Access ${access}"
echo "==================================================================="
echo "Access Key ID: $access_key_id"
echo "Secret Key ID: $secret_key_id"
echo "AWS_ACCESS_KEY_ID=$access_key_id AWS_SECRET_ACCESS_KEY=$secret_key_id"
echo "==================================================================="

gateway-mt run --server.address="0.0.0.0:7777" --auth-token=super-secret --auth-url=http://authservice:8000 --domain-name=gateway.local \
--tracing.enabled=true --tracing.sample=1 --tracing.agent-addr=tracing:5775 --debug.addr=0.0.0.0:5999