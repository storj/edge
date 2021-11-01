badgerauth
==========

Package badgerauth implements eventually consistent auth database built on top of [BadgerDB](https://dgraph.io/docs/badger/).

The implementation is based on the design from the [New Auth Database](https://review.dev.storj.io/c/storj/gateway-mt/+/6030) blueprint.

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
