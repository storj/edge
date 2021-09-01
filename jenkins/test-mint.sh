#!/usr/bin/env bash
set -uo pipefail

SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

echo "Performing apt update and installing dependencies"
apt update
apt install -y curl jq

# setup tmpdir for testfiles and cleanup
TMP=$(mktemp -d -t tmp.XXXXXXXXXX)
cleanup(){
	ret=$?
	echo "EXIT STATUS: $ret"
	rm -rf "$TMP"
}
trap cleanup EXIT

echo "Clone storj repo"
cd /home && git clone https://github.com/storj/storj.git --depth 1

bin_dir=/go/bin

build_binary(){
    sourcepath="$1"
    cmdpath="$2"
    mkdir -p "$sourcepath"
    cd "$sourcepath" && go build -o "$bin_dir" -race -v "$cmdpath"
}

echo "Build all needed binaries"
build_binary "/home/storj" "storj.io/storj/cmd/satellite"
build_binary "/home/storj" "storj.io/storj/cmd/storagenode"
build_binary "/home/storj" "storj.io/storj/cmd/storj-sim"
build_binary "/home/storj" "storj.io/storj/cmd/versioncontrol"
build_binary "/home/storj" "storj.io/storj/cmd/uplink"
build_binary "/home/storj" "storj.io/storj/cmd/identity"
build_binary "/home/storj" "storj.io/storj/cmd/certificates"
build_binary "/home/storj" "storj.io/storj/cmd/multinode"
build_binary "$SCRIPTDIR" "storj.io/gateway-mt/cmd/gateway-mt"
build_binary "$SCRIPTDIR" "storj.io/gateway-mt/cmd/authservice"

# install exact version of storj/gateway
go version
GOBIN=$bin_dir /usr/local/go/bin/go install storj.io/gateway@latest

echo "FINISHED INSTALLING"

export STORJ_NETWORK_DIR=$TMP

STORJ_NETWORK_HOST4=${STORJ_NETWORK_HOST4:-127.0.0.1}
STORJ_SIM_POSTGRES=${STORJ_SIM_POSTGRES:-""}

# make sure any previous storj-sim configuraton is deleted
storj-sim -x network destroy

echo "Set up storj-sim"
# setup the network
# if postgres connection string is set as STORJ_SIM_POSTGRES then use that for testing.
if [ -z "${STORJ_SIM_POSTGRES}" ]; then
	storj-sim -x --satellites 1 --host "$STORJ_NETWORK_HOST4" network setup
else
    echo "setting up with STORJ_SIM_POSTGRES"
	storj-sim -x --satellites 1 --host "$STORJ_NETWORK_HOST4" network --postgres="$STORJ_SIM_POSTGRES" setup
fi

# increase default metainfo rate limit for tests
sed -i 's/# metainfo.rate-limiter.enabled: true/metainfo.rate-limiter.enabled: false/g' "$(storj-sim network env SATELLITE_0_DIR)/config.yaml"
cat "$(storj-sim network env SATELLITE_0_DIR)/config.yaml" | grep "metainfo.rate-limiter.enabled"

storj-sim -x network run &

for i in {1..60}; do
    echo "Trying ${i} time for access grant"
    access_grant=$(storj-sim network env GATEWAY_0_ACCESS)
    if [ -n "${access_grant}" ]; then
        break
    fi
    sleep 1
done

if [ -z "${access_grant}" ]; then
    echo "Failed to find access_grant"
    exit 1
fi

echo "Found access grant: ${access_grant}"

satellite_node_url=$(storj-sim network env SATELLITE_0_ID)@$(storj-sim network env SATELLITE_0_ADDR)

if [ -z "${satellite_node_url}" ]; then
    echo "satellite_node_url is empty"
    exit 1
fi

authtoken="bob"
authservice_address="127.0.0.1:9191"
minio_url="http://127.0.0.1:7777/"

authservice run --allowed-satellites "${satellite_node_url}" --auth-token "${authtoken}" --listen-addr "${authservice_address}"  --endpoint="${minio_url}" --kv-backend="memory://" &
gateway-mt run --server.address 0.0.0.0:7777 --auth-url="http://${authservice_address}" --auth-token="${authtoken}" --domain-name="${GATEWAY_DOMAIN}" --insecure-log-all &

for i in {1..60}; do
    echo "Trying ${i} time to register access_grant with authservice"
    body='{"access_grant":"'"${access_grant}"'"}'
    json=$(curl -s -XPOST -H "Content-Type: application/json" -d "${body}" ${authservice_address}/v1/access)
    access_key_id=$(echo "${json}" | jq .access_key_id -r)
    secret_key=$(echo "${json}" | jq .secret_key -r)
    if [ -n "${access_key_id}" ]; then
        break
    fi
    sleep 1
done

if [ -z "${access_key_id}" ]; then
    echo "Failed to get access_key_id/secret_key"
    exit 1
fi

echo "All services running correctly"
echo "Finished access_key_id:${access_key_id},secret_key:${secret_key}"

sleep 1h
