badgerauth
==========

Package badgerauth implements eventually consistent auth database built on top of [BadgerDB](https://dgraph.io/docs/badger/).

The implementation is based on the design from the [New Auth Database](https://github.com/storj/gateway-mt/blob/3ef75f412a50118d9d910e1b372e126e6ffb7503/docs/blueprints/new-auth-database.md) blueprint.

## Usage

_TODO(artur): fill up this section when more of the badgerauth package is carved out._

## Operations

_TODO(artur): fill up this section when more of the badgerauth package is carved out._

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

#### Handling out of sync nodes

Backgroud: https://github.com/storj/gateway-mt/blob/3ef75f412a50118d9d910e1b372e126e6ffb7503/docs/blueprints/new-auth-database.md#replication-chore

The blueprint stated that we would need to use some time comparisons, but after some thought, it became evident time comparisons can be avoided at all. However, it also became evident that nodes would have to preserve [the global atomic counter](https://github.com/storj/gateway-mt/blob/3ef75f412a50118d9d910e1b372e126e6ffb7503/docs/blueprints/new-auth-database.md#replication-algorithm) for themselves and all nodes they know about.

To make it clearer why, consider the following situation that wasn't considered in the blueprint:

Node A's replication log:

| ID | Clock Value | Key Hash (Record ID) |  State  | TTL |
|:--:|:-----------:|:--------------------:|:-------:|:---:|
| A  | 1           | X                    | CREATED |     |
| A  | 2           | Y                    | CREATED |     |
| A  | 3           | Z                    | CREATED | 24h |
| B  | 9           | Z                    | DELETED | 24h |

Node C's replication log:

| ID | Clock Value | Key Hash (Record ID) |  State  | TTL |
|:--:|:-----------:|:--------------------:|:-------:|:---:|
| A  | 1           | X                    | CREATED |     |
| A  | 2           | Y                    | CREATED |     |
| A  | 3           | Z                    | CREATED |     |

If C does not sync with A in 24h (or other tombstone expiration period), then:

1. C never deletes Z, which should
2. A might sync with C and restore Z (!)

To avoid this, we want to keep track of all nodes' clock values regardless of the last value in the replication log (we thought we could get away with getting the last value from the replication log only). This way, A knows that its last clock value was 3, and respectively:

1. A will consider C out of sync
2. If A syncs with C, it will present 3 as the last value and not 2

The problem with this approach is that we might introduce transaction conflicts at Put, Delete and Invalidate actions ([read more on how transactions are implemented in BadgerDB](https://dgraph.io/blog/post/badger-txn/)) since global count will be tracked under a non-unique key. To avoid them, we could sacrifice some durability guarantees (TODO(artur): write more about this).
