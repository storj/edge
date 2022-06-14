# Load Testing the Link Sharing Service

## Background

The scripts in this directory are trial attempts to load test the Link Sharing Service.  We've
seen slow down of the entire network stack in certain environments.  There is growing evidence
that this issue may be related to congestion control or network stack misconfiguration.

These tests are not designed to be run as part of a regular regression test, they are for
troubleshooting only.

## Usage

First, export the access grant you want to use as a shell variable so our scripts can use this.
Note the space in front to avoid it being written to your shell history!

```shell
 export ACCESS_GRANT=123
```

If you don't have this already, create a new random bucket, uploading 100x 128MB randomly
generated files:

```shell
./generate-files-uplink.sh
```

Now you can run the load test by giving the `test-linksharing.sh` script the bucket, concurrency
limit, and linksharing you want to test against. Note that you need at least as many files as
the concurrency, as every concurrent download is a different file in the bucket.

```shell
./test-linksharing.sh mybucket 100 https://link.storjshare.io
```
