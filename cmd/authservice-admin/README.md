# authservice-admin

This is a tool used to interact directly with records stored in auth database.

## Install

```console
$ go install storj.io/edge/cmd/authservice-admin
```

## Usage

The tool supports multiple backends (separately and to be used at once). Specify them by supplying the `--storage.*` flags.

Commands use `<key>` as a common argument to look up a record. This argument can either be the access key ID (base32 encoded, 28 character string), or a SHA-256 hash of the access key (hexadecimal encoded, 64 character string).

Logging can be enabled by using the `--log.enabled` flag.

Example command:

```console
$ authservice-admin record show jwaohtj3dhixxfpzhwj522x7z3pb --storage.spanner.creds path/to.json --storage.spanner.db-name=projects/P/instances/I/databases/D
```

## Interacting with Satellite admin

Optionally you can supply [satellite admin](https://github.com/storj/storj/tree/main/satellite/admin) addresses for this tool to interact with the satellite.

The satellite admin addresses are provided to the command comma separated, and each entry is joined by `=` in the form of `<address>=<admin-base-url>=<admin-token>`.

* `<address>` is the satellite address from a satellite node URL, e.g. `us1.storj.io:7777`
* `<admin-base-url>` is the address to the satellite admin for the satellite. This needs to be forwarded from the remote satellite deployment before it can be used here. e.g. `http://localhost:10005`
* `<admin-token>` is the authentication token required to authenticate with the satellite admin API

```console
$ authservice-admin record show jwaohtj3dhixxfpzhwj522x7z3pb \
	--storage.spanner.creds path/to.json \
	--storage.spanner.db-name=projects/P/instances/I/databases/D \
	--satellite-addresses satellite1:7777=http://localhost:10005=12345,satellite2:7777=http://localhost:10006=45678"
```

## Record commands

### Show

Show a record. By default, text output is shown. You can change this to JSON by specifying `--output json` or `-o json`.

Note that macaroon head is hex encoded. Encrypted access key, and encrypted secret key are base64 encoded in the output.

```console
$ authservice-admin record show <key>
```

### Invalidate

Invalidates an access key so it's no longer usable, and an error will be returned if attempted to be used on a Storj S3 Gateway, or Link Sharing Service.

```console
$ authservice-admin record invalidate <key> <reason>
```

### Unpublish

Restricts an access key from being used in publicly shared Link Sharing Service URLs. In order to continue using it, signed requests using the secret key will be required.

```console
$ authservice-admin record unpublish <key>
```

### Delete

Deletes a access key record, and any corresponding replication log entries.

If satellite admin addresses are configured, this will also delete the API key on the satellite.

```console
$ authservice-admin record delete <key>
```

## Links commands

### Inspect

Inspect one or more shared links located in a text file. These links can be from Link Sharing Service, or S3 gateway presigned links. By default, text output is shown. You can change this to JSON by specifying `--output json` or `-o json`.

Note that macaroon head is hex encoded. Encrypted access key, and encrypted secret key are base64 encoded in the output.

If satellite admin addresses are configured, more details about the owner are also included in the output.

```console
$ authservice-admin links inspect /tmp/links.txt
```

### Revoke

Revoke one or more shared links located in a text file.

This command requires the satellite admin addresses to be configured, so the API key can be deleted on the satellite.

It also freezes free-tier accounts. This can be disabled with the flag `--freeze-accounts=false`.

```console
$ authservice-admin links revoke /tmp/links.txt
```
