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

TODO(artur): we removed invalidation/deletion, and this differs from the blueprint very much. Update the blueprint or write what happened here.
