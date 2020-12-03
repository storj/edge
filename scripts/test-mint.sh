#!/usr/bin/env bash
set -uo pipefail

SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

apt update
apt install -y curl jq unzip

# setup tmpdir for testfiles and cleanup
export TMP=$(mktemp -d -t tmp.XXXXXXXXXX)
cleanup(){
	rm -rf "$TMP"
}
trap cleanup EXIT

bin_dir=/go/bin

build_binary(){
    sourcepath="$1"
    cmdpath="$2"
    mkdir -p "$sourcepath"
    cd $sourcepath && go build -o $bin_dir -race -v $cmdpath
}

cd /home && git clone https://github.com/storj/storj.git --depth 1

build_binary "/home/storj" "storj.io/storj/cmd/satellite"
build_binary "/home/storj" "storj.io/storj/cmd/storagenode"
build_binary "/home/storj" "storj.io/storj/cmd/storj-sim"
build_binary "/home/storj" "storj.io/storj/cmd/versioncontrol"
build_binary "/home/storj" "storj.io/storj/cmd/uplink"
build_binary "/home/storj" "storj.io/storj/cmd/identity"
build_binary "/home/storj" "storj.io/storj/cmd/certificates"
build_binary "$SCRIPTDIR" "storj.io/gateway-mt/cmd/gateway-mt"
build_binary "$SCRIPTDIR" "storj.io/gateway-mt/cmd/authservice"

# install exact version of storj/gateway
cd /home && mkdir -p .build/gateway-tmp &&
    cd .build/gateway-tmp && go mod init gatewaybuild &&
    GO111MODULE=on go build -o $bin_dir storj.io/gateway

echo "FINISHED INSTALLING"

export STORJ_NETWORK_DIR=$TMP

STORJ_NETWORK_HOST4=${STORJ_NETWORK_HOST4:-127.0.0.1}
STORJ_SIM_POSTGRES=${STORJ_SIM_POSTGRES:-""}

# make sure any previous storj-sim configuraton is deleted
storj-sim -x network destroy

# setup the network
# if postgres connection string is set as STORJ_SIM_POSTGRES then use that for testing.
if [ -z ${STORJ_SIM_POSTGRES} ]; then
	storj-sim -x --satellites 1 --host $STORJ_NETWORK_HOST4 network setup
else
    echo "setting up with STORJ_SIM_POSTGRES"
	storj-sim -x --satellites 1 --host $STORJ_NETWORK_HOST4 network --postgres=$STORJ_SIM_POSTGRES setup
fi

storj-sim -x network run &

for i in {1..60}; do
    echo "Trying ${i} time for access grant"
    access_grant=$(storj-sim network env | grep GATEWAY_0_ACCESS= | cut -d "=" -f2)
    if [ ! -z ${access_grant} ]; then
        break
    fi
    sleep 1
done

if [ -z ${access_grant} ]; then
    echo "Failed to find access_grant"
    exit 1
fi

echo "Found access grant: ${access_grant}"

satellite_node_url=$(uplink access inspect ${access_grant} | grep Satellite | cut -d ":" -f2,3 | xargs)

if [ -z ${satellite_node_url} ]; then
    echo "satellite_node_url is empty"
    exit 1
fi

authtoken="bob"
authservice_address="localhost:8000"

authservice run --allowed-satellites ${satellite_node_url} --auth-token ${authtoken} &
MINIO_NOAUTH_ENABLED=enable MINIO_NOAUTH_SERVER_ADDR="${authservice_address}" MINIO_NOAUTH_AUTH_TOKEN=${authtoken} gateway-mt run --server.address 0.0.0.0:7777 &

for i in {1..60}; do
    echo "Trying ${i} time to register access_grant with authservice"
    body=$(echo '{"access_grant":"'"${access_grant}"'"}')
    json=$(curl -s -XPOST -H "Content-Type: application/json" -d ${body} localhost:8000/v1/access)
    access_key_id=$(echo ${json} | jq .access_key_id -r)
    secret_key=$(echo ${json} | jq .secret_key -r)
    if [ ! -z ${access_key_id} ]; then
        break
    fi
    sleep 1
done

if [ -z ${access_key_id} ]; then
    echo "Failed to get access_key_id/secret_key"
    exit 1
fi

# Install the awscli so I can do a quick test, ensure that all services are running.
cd /home && curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" && \
    unzip awscliv2.zip && \
    ./aws/install \

for i in {1..60}; do
    ret=$(AWS_ACCESS_KEY_ID=${access_key_id} AWS_SECRET_ACCESS_KEY=${secret_key} /usr/local/bin/aws s3 ls --endpoint http://localhost:7777 2>&1)
    if [ -z $ret ]; then
        break
    fi
    sleep 1
done

if [ ! -z $ret ]; then
    echo "awscli failed to verify everything is working"
    echo $ret
    exit 1
fi

echo "All services running correctly"
echo "Finished access_key_id:${access_key_id},secret_key:${secret_key}"

sleep 1h
