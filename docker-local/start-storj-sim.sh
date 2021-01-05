#!/usr/bin/env bash

set -e

export PATH=$GOPATH/bin:$PATH

cd /code
make install-sim

storj-sim network destroy

until storj-sim network setup --host storjsim; do
    echo "postgres not available, sleeping"
    sleep 1
done

storj-sim network run
