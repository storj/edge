# authservice-admin

This is a tool used to interact directly with records stored in a badgerauth backed authservice.

## Install

```console
$ go install storj.io/gateway-mt/cmd/authservice-admin
```

## Usage

First, collect the node addresses for the badgerauth cluster that you need to connect to. If you're only wanting to display a record, it's okay to use a single address to connect to.

In order to authenticate with badgerauth nodes, you need to set up a directory with certificates and keys. The following files are required:

* `ca.crt`. The CA cert the cluster uses for mutual TLS communication.
* `client.key`. A key used to authenticate to cluster nodes.
* `client.crt`. A cert used to authenticate to cluster nodes.

Steps to create a new key and cert are as follows, using the CA key:

```console
$ openssl genrsa -out certs/client.key 2048
$ chmod 400 certs/client.key

$ cat << EOF > client.cnf
[ req ]
prompt=no
distinguished_name = distinguished_name

[ distinguished_name ]
organizationName = Storj
EOF

$ openssl req -new -config client.cnf -key certs/client.key -out client.csr -batch
$ openssl ca -config ca.cnf -keyfile my-safe-directory/ca.key -cert certs/ca.crt -policy signing_policy -extensions signing_client_req -out certs/client.crt -outdir certs/ -in client.csr -batch
```

More details on the CA setup can be found in the [badgerauth documentation](../../pkg/auth/badgerauth/README.md).

Commands use `<key>` as a common argument to look up a record. This argument can either be the access key ID (base32 encoded, 28 character string), or a SHA-256 hash of the access key (hexadecimal encoded, 64 character string.)

Logging can be enabled by using the `--log.enabled` flag.

Example command:

```console
$ authservice-admin record show jwaohtj3dhixxfpzhwj522x7z3pb --certs-dir ~/.authservice-admin/certs --node-addresses node1:20004,node2:20004
```

If running a command to modify a record, all nodes should be listed in the `--node-addresses` flag so the record is updated simultaneously on all the nodes. For `record show` commands, all node addresses will be consulted, but only one response will be used.

### Commands

#### Show record

Show a record. By default, tabbed output is shown. You can change this to JSON by specifying `--output json` or `-o json`.

To output more details with tabbed output, you can use `--expanded` or `-x`.

Note that macaroon head is hex encoded. Encrypted access key, and encrypted secret key are base64 encoded in the output.

```console
$ authservice-admin record show <key>
```

#### Invalidate record

Invalidates an access key so it's no longer usable, and an error will be returned if attempted to be used on a Storj S3 Gateway, or Linksharing.

```console
$ authservice-admin record invalidate <key> <reason>
```

#### Unpublish record

Restricts an access key from being used in publicly shared Linksharing URLs. In order to continue using it, signed requests using the secret key will be required.

```console
$ authservice-admin record unpublish <key>
```

#### Delete record

Deletes a access key record, and any corresponding replication log entries.

```console
$ authservice-admin record delete <key>
```
