# Edge Services Handbook

_This guide is mostly useful for people (including Storj Labs employees) who want to develop and/or gain more in-depth knowledge about Storj's edge services._

## Overview

Edge services bridge the gap between [the native integration](https://github.com/storj/uplink) and existing applications written to talk with S3 object storage (Gateway-ST and Gateway-MT). Link Sharing Service allows to quickly share a file or an entire directory via URL.

### Repositories

- [MinIO fork upon which Gateway-ST and Gateway-MT are based](https://github.com/storj/minio)
- [Gateway-ST](https://github.com/storj/gateway-st)
- [Gateway-MT and Link Sharing Service](https://github.com/storj/gateway-mt) (this repository)

<!-- TODO(artur): dependency graph might be nice. -->

#### What is Auth Service (included in this repository) and why do we need it?

Auth Service maps existing access grants to S3-specific Access Key ID/Secret Access Key pairs on demand. The primary reason for using Auth Service is that it's hard to pass long access grants in Access Key ID/Secret Access Key. See [this](https://github.com/storj/gateway-mt/blob/7113bd0a4b0e746da9fa0374f216d23d075c5c17/docs/blueprints/security-auth.md#design) for a more in-depth explanation of how Gateway-MT works with Auth Service. Link Sharing Service can work with and without Auth Service (it's easier and more secure with Auth Service). Gateway-ST does not need Auth Service.

### Roadmap

See [Public Roadmap filtered for Edge Team](https://github.com/orgs/storj/projects/23/views/15?filterQuery=label%3A%22team-edge%22).

See also [the GitHub project including current items the team is working on](https://github.com/orgs/storj/projects/29).

## Service-specific documentation

1. [Gateway-ST (also Gateway-MT's object layer) documentation](https://github.com/storj/gateway-st/blob/main/README.md)
2. [Auth Service, Gateway-MT and Link Sharing Service](README.md)
3. [Blueprints](docs/blueprints/) (see [this](https://github.com/storj/storj/blob/main/docs/blueprints/README.md) for an explanation of what blueprints are)

## Development

### How to run everything locally?

TODO(artur): write about this. Present different approaches, including storj/up.

### Testing

#### Correctness

A suite of integration tests for Gateway-MT can be run on the checked out code.

`make integration-run` will start a new integration environment using Docker and run all the integration tests.

At the end of the run, you can run `make integration-env-purge` to remove the integration environment.

This requires `docker`, `git`, and `openssl` to be installed on your local machine for this to work.

##### mint

We run mint tests based on MinIO's mint ([gateway-mint](https://github.com/storj/gateway-mint)) on every commit to Gateway-MT against Gateway-MT, as well as in the fork's repository itself.

To run the tests:

`make integration-env-start integration-mint-tests`

You can also run a specific test using the `TEST` environment variable:

`TEST=aws-sdk-php make integration-mint-tests`

##### ceph/splunk-s3-tests

We run S3 tests based on Splunk's fork (which is better suited for us) of Ceph's S3 tests ([splunk-s3-tests](https://github.com/storj/splunk-s3-tests)) on every commit to Gateway-MT against Gateway-MT, as well as in the fork's repository itself.

To run the tests:

`make integration-env-start integration-splunk-tests`

#### Performance

We currently don't run performance tests. We are planning to performance-test Gateway-MT/Gateway-ST using [COSBench](https://github.com/intel-cloud/cosbench) and [warp](https://github.com/minio/warp).

## Infrastructure

### Monitoring

#### Metrics

We collect metrics and telemetry metrics for Gateway-ST (if consent has been granted), similarly to what [this blueprint](https://github.com/storj/storj/blob/e486a073cbb812771e30893b4c278f09776acf47/docs/blueprints/uplink-telemetry.md) proposes.
