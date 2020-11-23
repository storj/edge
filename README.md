# S3 "Stargate" Gateway

S3-compatible gateway for Storj V3 Network, based on [MinIO](https://github.com/minio/minio).

[![Go Report Card](https://goreportcard.com/badge/storj.io/stargate)](https://goreportcard.com/report/storj.io/stargate)
[![Go Doc](https://img.shields.io/badge/godoc-reference-blue.svg?style=flat-square)](https://pkg.go.dev/storj.io/stargate)
![Beta](https://img.shields.io/badge/version-beta-green.svg)

<img src="https://github.com/storj/storj/raw/master/resources/logo.png" width="100">

Storj is building a decentralized cloud storage network.
[Check out our white paper for more info!](https://storj.io/white-paper)

----

Storj is an S3-compatible platform and suite of decentralized applications that
allows you to store data in a secure and decentralized manner. Your files are
encrypted, broken into little pieces and stored in a global decentralized
network of computers. Luckily, we also support allowing you (and only you) to
retrieve those files!

# Documentation

* [Using the S3 Gateway](https://documentation.tardigrade.io/api-reference/s3-gateway)

# How to run stargate with auth service
- Run auth service
    - `--auth-token` is used to authenticate `GET` request. We will need to pass the same value into `stargate` so it can talk to the `authservice` instance.
    - `--allowed-satellites` is the satellite node url.
        - we can use uplink cli to get the satellite node url that's associated with a given access grant
        ```
        uplink access inspect "my-access-grant"
        ```
    ```
    authservice run --auth-token "super-secret" --allowed-satellites="satellite-node-url"
    ```
- Run stargate
Currently, auth service configuration is passed in to `minio` through environment variables:
    - `MINIO_NOAUTH_ENABLED=enable` enables stargate to use our auth service implementation
    - `MINIO_NOAUTH_AUTH_TOKEN` sets the auth token that's used to authenticate with our auth service. This should be set to the same value as the `--auth-token` in `authservice` command
    - `MINIO_NOAUTH_AUTH_URL` defines the address of our auth service instance. It's default to `http://localhost:8000`
    ```
    MINIO_NOAUTH_ENABLED=enable MINIO_NOAUTH_AUTH_TOKEN="bob" MINIO_NOAUTH_SERVER_ADDR=localhost:8000 stargate run
    ```
- Register an access grant with auth service
    ```
    uplink access register "my-access-grant" --auth-service https://localhost:8000
    ```
    After registering an access grant with the auth service, you will have the s3 credential, `Access Key Id` and `Secret Key`
    You can use that credential to configure an s3 client to talk to storj network through the stargate

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

We use the minio mint testsuite to ensure our compatibility to the S3 API. As some S3 methods are not supported yet, we use a custom build that you can run it against any endpoint using docker.  The majority of these tests are defined in https://github.com/storj/minio/blob/master/mint/mint.sh.

To build our custom image and tag it as storj/mint:
```
docker build --pull https://github.com/storj/minio.git#main -f Dockerfile.mint -t storj/mint
```
To run the tests against the endpoint `endpoint_address` (using the `HOST:PORT` format), use:
```
docker run -e SERVER_ENDPOINT=endpoint_address -e ACCESS_KEY=myaccesskey -e SECRET_KEY=mysecretkey -e ENABLE_HTTPS=0 storj/mint
```
The `ENABLE_HTTPS` flag indicates if https should be used (`ENABLE_HTTPS=1`)

# Stargate + storj-sim + Minio Mint test workflow
Stargate is designed to becompatible with the Minio Mint's Docker-based test suite.  If you'd like to use storj-sim to test local changes to Mint, run these commands:

```
storj-sim network setup
storj-sim network run
```

```
authservice run  --auth-token "super-secret" --allowed-satellites="$(storj-sim network env SATELLITE_0_ADDR)"
```

```
MINIO_NOAUTH_ENABLED=enable MINIO_NOAUTH_AUTH_TOKEN="super-secret" MINIO_NOAUTH_AUTH_URL=localhost:8000 stargate run
```

```
docker build . -f Dockerfile.mint -t storj/mint
uplink access register $(storj-sim network env GATEWAY_0_ACCESS) --auth-service http://localhost:8000 --aws-profile storjsim
export ACCESS_KEY=$(aws configure get aws_access_key_id --profile=storjsim)
export SECRET_KEY=$(aws configure get aws_secret_access_key --profile=storjsim)
docker run -e SERVER_ENDPOINT=host.docker.internal:7777 -e ACCESS_KEY=$ACCESS_KEY -e SECRET_KEY=$SECRET_KEY -e ENABLE_HTTPS=0 storj/mint
```
Note that Linux users may need alter the above commmand to `SERVER_ENDPOINT=localhost:7777` to use or the `--add-host=host.docker.internal:host-gateway` flag.

# License

This software is distributed under the
[AGPLv3](https://www.gnu.org/licenses/agpl-3.0.en.html) license.

# Support

If you have any questions or suggestions please reach out to us on
[our community forum](https://forum.storj.io/) or
email us at support@tardigrade.io.
