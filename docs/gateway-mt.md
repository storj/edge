# Multitenant S3 Gateway

S3-compatible gateway for Storj V3 Network, based on [MinIO](https://github.com/minio/minio).

If you're looking for the easier-to-setup Single Tenant Gateway, check out [Gateway-ST](https://github.com/storj/gateway-st).

----

Storj is an S3-compatible platform and suite of decentralized applications that
allows you to store data in a secure and decentralized manner. Your files are
encrypted, broken into little pieces and stored in a global decentralized
network of computers. Luckily, we also support allowing you (and only you) to
retrieve those files!

# Documentation

* [Using the S3 Gateway](https://docs.storj.io/api-reference/s3-gateway)

# How to run gateway-mt with auth service

## Run auth service

    - `--auth-token` is used to authenticate `GET` request. We will need to pass the same value into `gateway-mt` so it can talk to the `authservice` instance.
    - `--allowed-satellites` is the satellite node url (this must include the identity for non-DCS satellites).
        - we can use uplink cli to get the satellite node url that's associated with a given access grant
        - allowed-satellites may alternatively include lists of satellites, such as https://www.storj.io/dcs-satellites
        ```
        uplink access inspect "my-access-grant"
        ```
    - `--kv-backend` is the connection string for the key-value store backend.  Valid values may include `pgxcockroach://...`, `pgx://...`, or `memory://`
    ```bash
    # migration automatically applies or updates DB schema in use.
    # shouldn't be run against the same database by multiple instances at once.
    authservice run --migration --auth-token "super-secret" --allowed-satellites="satellite-node-url" --kv-backend="pgxcockroach://..."
    ```
## Run gateway-mt


Gateway-MT requires the following command line parameters:
      - `--auth.token` sets the auth token that's used to authenticate with our auth service. This should be set to the same value as the `--auth.token` in `authservice` command.
      - `--auth.base-url` defines the address of our auth service instance. It's default to `http://localhost:20000`.
      - `--domain-name` allows the gateway-mt to work with virtual hosted style requests. For example, if the `MINIO_DOMAIN` variable is set to `asdf.com`, then a request to `bob.asdf.com` will be interpreted as specifying the bucket `bob`.

    gateway-mt run --auth.token="super-secret" --auth.base-url=http://localhost:20000 --domain-name=localhost

    - Enable debug server
        - by default, the debug server is disabled
        - `gateway-mt run --debug.addr=debug-server-address` enables debug server.

## Register an access grant with auth service
    ```
    uplink access register "my-access-grant" --auth-service https://localhost:20000
    ```
    After registering an access grant with the auth service, you will have the s3 credential, `Access Key Id` and `Secret Key`
    You can use that credential to configure an s3 client to talk to storj network through the gateway-mt


# How to configure gateway-mt with a base and wildcard certificates

Gateway-MT will load certificates from a directory provided.

The following is a complete walk through for doing this locally.

First we generate two certificates for use (one static and one wildcard):

```
wget -O generate_cert.go 'https://golang.org/src/crypto/tls/generate_cert.go?m=text'

mkdir -p certs

pushd certs
go run ../generate_cert.go -host 'gateway.local'
ln -s cert.pem cert.crt
ln -s key.pem cert.key
popd

mkdir -p certs/wildcard

pushd certs/wildcard
go run ../generate_cert.go -host '*.gateway.local'
ln -s cert.pem cert.crt
ln -s key.pem cert.key
popd
```

After running these commands you should have a `certs` directory that contains:

```
certs/
certs/cert.pem
certs/key.pem
certs/wildcard
certs/wildcard/cert.pem
certs/wildcard/key.pem
certs/wildcard/public.crt
certs/wildcard/private.key
certs/public.crt
certs/private.key
```

Inspecting the certificates should reveal that they contain the correct subject names:

```
openssl x509 -in certs/public.crt -text
openssl x509 -in certs/wildcard/public.crt -text
```

Now you can start Gateway-MT with the `--cert-dir` and `--insecure-disable-tls=false`
flags, which will configure the server to handle HTTPS traffic.

You can change the interface and port the server listens on using `--server.address-tls`.

Use the uplink CLI to register an access grant (replace `$ACCESS` with an access grant):

```
uplink access register --auth-service http://127.0.0.1:20000 $ACCESS
```

Export the provided access key id and secret:

```
export AWS_ACCESS_KEY_ID=some_access_key_id
export AWS_SECRET_ACCESS_KEY=some_secret_key
```

Now we can use the AWS CLI with special DNS resolution to confirm that a `test`
bucket can be accessed using virtual host style requests:

```
docker run -it --rm --net=host \
  --add-host=test.gateway.local:127.0.0.1 \
  --add-host=gateway.local:127.0.0.1 \
  -e AWS_SECRET_ACCESS_KEY \
  -e AWS_ACCESS_KEY_ID \
  --entrypoint /bin/bash amazon/aws-cli
aws configure set default.s3.addressing_style virtual
aws s3 ls --endpoint https://gateway.local:20011 --no-verify-ssl --debug
```

The request should succeed and the debug output should contain lines like
`MainThread - botocore.utils - DEBUG - Using S3 virtual host style addressing.`

# S3 API Compatibility using Docker
The following S3 methods are supported:
- HeadBucket
- CreateBucket
- DeleteBucket
- ListBuckets
- HeadObject
- PutObject
- GetObject
- DeleteObject
- DeleteObjects
- ListObjects
- ListObjectsV2

We run a fork of the minio/mint repository at [storj/gateway-mint](https://github.com/storj/gateway-mint/)
used to test correctness of the gateway.

To run the tests:

```
docker run --rm \
	-e SERVER_ENDPOINT=endpoint_address \
	-e ACCESS_KEY=myaccesskey \
	-e SECRET_KEY=mysecretkey \
	-e ENABLE_HTTPS=0 \
	storjlabs/gateway-mint
```

# Using docker-compose for local development

For convenience in local testing, a docker-compose file can be found in
`docker-local/docker-compose.yml`. This section explains how to use this
properly for local testing.

## Set environment variables

The compose script requires two environment variables to run correctly:

- `STORJ_SRC_DIR`: This is the path to your storj.io/storj source code.
- `GATEWAY_SRC_DIR`: This is the path to your storj.io/gateway-mt source code.

Example:

`STORJ_SRC_DIR=$HOME/storj.io/storj GATEWAY_SRC_DIR=$HOME/storj.io/gateway-mt docker-compose up`

This is only an example, the correct paths for your machine must be provided.

## Start the docker containers

Navigate to the `docker-local` folder and run `docker-compose up`.

The first time it runs it will pull docker containers and build all the source
code and pull external go modules. This will all be cached.

When the processes finishes, the `gateway-mt` container will output the
following (an example):

```
gateway-mt_1   | ===================================================================
gateway-mt_1   | Access 1NfEEWDxPUob3Qib9EhjP4rdCw4GnnwT81aNwV2txywscPHDpBsTmT6VjrhLGBmJjULdNZA8TnvYC5vSYvxgSfDW2h5P9D9cow6gmHoqaNeGT5DcWH7L9FinpBgjM3S1cinHSQwufsRLzFtYd3CohW4QDohcASreWqPB8HxwAi5M1UQMPUgSftXZzGKPCkvRDjkCkySyfR93gkfxqStn873ScKnYwvXSXjjk9KiFSZ2KbAf1do1a3sJsT
gateway-mt_1   | ===================================================================
gateway-mt_1   | ========== CREDENTIALS ===================================================================
gateway-mt_1   | Access Key ID:  jxjlhpevlqi6wg5y4lqj3kg5gu3a
gateway-mt_1   | Secret Key   :  jzzqymrvhwxos7hfynucwnr4sn2zphxfxyq52k7guicuarmhc5gta
gateway-mt_1   | Endpoint     :  http://localhost:20010
gateway-mt_1   | ===================================================================
```

The access is the access for storj-sim, in case you want to use it for something
else. (See NOTE below.)

The gateway-mt registers this access with the authservice for you, and the
access key and secret key are printed out also.

You now should be able to connect to the gateway-mt at `http://localhost:20010`
using those credentials.

NOTE: The satellite address embedded in the access is strange: something like
`1RztXfxeGrQMku8SRfFeLbVwdqq1XbMm59Gjapck3SCmfXB6WR@storjsim:10000`. This
`storjsim` address is due to docker's internal networking. If you need to use
this access locally, you need to make your computer resolve `storjsim` to
`localhost`.

## Development workflow

After it is running, if you make code changes and wish to test them, simply do
the following:

- Stop the containers with `docker-compose down`
- Start the containers again with `docker-compose up`

This will build the code again, but should only build code that has changed, and
will provide you with new credentials.

# Gateway MT + storj-sim + Minio Mint test workflow
Gateway MT is designed to becompatible with the Minio Mint's Docker-based test suite.  If you'd like to use storj-sim to test local changes to Mint, run these commands:

```
storj-sim network setup
storj-sim network run
```

```
authservice run --auth-token "super-secret" --allowed-satellites="$(storj-sim network env SATELLITE_0_ID)@" --endpoint=http://localhost:20010 --kv-backend="memory://"
```

```
gateway-mt run --auth.token="super-secret" --auth.base-url=http://localhost:20000 --domain-name=localhost
```

```
export $(uplink access register $(storj-sim network env GATEWAY_0_ACCESS) --auth-service http://localhost:20000 --format env)
docker run -e SERVER_ENDPOINT=host.docker.internal:20010 -e ACCESS_KEY=$AWS_ACCESS_KEY_ID -e SECRET_KEY=$AWS_SECRET_ACCESS_KEY -e ENABLE_HTTPS=0 storjlabs/gateway-mint
```
Note that Linux users may need alter the above commmand to `SERVER_ENDPOINT=localhost:20010` to use or the `--add-host=host.docker.internal:host-gateway` flag.

# License

This software is distributed under the
[AGPLv3](https://www.gnu.org/licenses/agpl-3.0.en.html) license.

# Support

If you have any questions or suggestions please reach out to us on
[our community forum](https://forum.storj.io/) or
email us at support@storj.io.
