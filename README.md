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
docker build --pull https://github.com/storj/minio.git#storj -f Dockerfile.mint -t storj/mint
```
To run the tests against the endpoint `endpoint_address` (using the `HOST:PORT` format), use:
```
docker run -e SERVER_ENDPOINT=endpoint_address -e ACCESS_KEY=myaccesskey -e SECRET_KEY=mysecretkey -e ENABLE_HTTPS=0 storj/mint
```
The `ENABLE_HTTPS` flag indicates if https should be used (`ENABLE_HTTPS=1`)



# License

This software is distributed under the
[AGPLv3](https://www.gnu.org/licenses/agpl-3.0.en.html) license.

# Support

If you have any questions or suggestions please reach out to us on
[our community forum](https://forum.storj.io/) or
email us at support@tardigrade.io.
