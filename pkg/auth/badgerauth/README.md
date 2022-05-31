badgerauth
==========

Package badgerauth implements eventually consistent auth database built on top of [BadgerDB](https://dgraph.io/docs/badger/).

The implementation is based on the design from the [New Auth Database](https://github.com/storj/gateway-mt/blob/3ef75f412a50118d9d910e1b372e126e6ffb7503/docs/blueprints/new-auth-database.md) blueprint.

## Usage

_TODO(artur): fill up this section when more of the badgerauth package is carved out._

## Operations

_TODO(artur): fill up this section when more of the badgerauth package is carved out._

## Schema

### [`NodeID`](nodeid.go)

Contains the local node ID, to identify it in a cluster.

#### Key

Name: `node_id`

#### Value

Type: `[32]byte` / [`NodeID`](nodeid.go)

### [`Clock`](clock.go)

Contains the logical time of a node.

#### Key

Name: `clock_value/NodeID`

| Name   | Type                               |
| ------ | ---------------------------------- |
| NodeID | `[32]byte` / [`NodeID`](nodeid.go) |

#### Value

Type: `uint64` / [`Clock`](clock.go). Big-endian byte order.

### [`ReplicationLogEntry`](replication_log.go)

A log corresponding to every auth record, used for node replication. Note that
the key contains the replication log entry itself.

#### Key

Name: `replication_log/NodeID/Clock/KeyHash/State`

| Name    | Type                                                                  |
| ------- | --------------------------------------------------------------------- |
| NodeID  | `[32]byte` / [NodeID](nodeid.go)                                      |
| Clock   | `uint64` / [Clock](clock.go). Big-endian byte order.                  |
| KeyHash | `[32]byte` / [KeyHash](../authdb/kv.go)                               |
| State   | `int32` / [Record_State](pb/badgerauth.pb.go). Big-endian byte order. |

#### Value

Type: nil

### [`Record`](pb/badgerauth.pb.go)

The auth record containing encrypted access grant, and metadata fields.

#### Key

Name: `KeyHash`

| Name    | Type                                      |
| ------- | ----------------------------------------- |
| KeyHash | `[32]byte` / [`KeyHash`](../authdb/kv.go) |

#### Value

Type: [`Record`](pb/badgerauth.pb.go)

| Name                 | Type                                          |
| -------------------- | --------------------------------------------- |
| CreatedAtUnix        | `int64`                                       |
| Public               | `bool`                                        |
| SatelliteAddress     | `string`                                      |
| MacaroonHead         | `[]byte`                                      |
| ExpiresAtUnix        | `int64`                                       |
| EncryptedSecretKey   | `[]byte`                                      |
| EncryptedAccessGrant | `[]byte`                                      |
| InvalidationReason   | `string`                                      |
| InvalidatedAtUnix    | `int64`                                       |
| State                | `int32` / [Record_State](pb/badgerauth.pb.go) |

## Development

### Regenerating protobufs

To install dependencies, execute

```sh
make badgerauth-install-dependencies
```

Dependency installation target support Linux using `apt` or `apt-get` and MacOS using [Homebrew](https://brew.sh/).

To regenerate protobufs, change the directory to `pkg/auth/badgerauth/pb` and

```sh
go generate
```

### Production Owner tools

_TODO(artur): fill up this section when more of the badgerauth package is carved out._

### Implementation details

Implementation details provide more context to how designs from the blueprint were implemented and can be useful for understanding existing code and/or debugging.

TODO(artur): we removed invalidation/deletion, and this differs from the blueprint very much. Update the blueprint or write what happened here.
