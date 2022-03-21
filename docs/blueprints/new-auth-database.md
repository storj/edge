# New Auth Database

## Abstract

We want to replace CockroachDB with our in-house solution. This solution will be
based on a key-value store like BadgerDB and use replication with relaxed
consistency constraints. We never really needed strong consistency, so an
eventually consistent database will allow us to overcome some hiccups we had
using strongly consistent CockroachDB. Specifically, it should allow us to
reduce the number of requests not handled due to cross-regional latency, lower
maintenance costs, make some queries less complicated due to the nature of our
data model and make it easier for other people (e.g. community) to run
authservice in a cluster.

## Background

Currently, we use CockroachDB with one table for authservice's database. At the
time of writing this blueprint, we deploy authservice in three geographical
"regions" (parts of the world): Asia-Pacific, Europe and North America. These
three regions are connected together to form a global cluster. The database is
strongly consistent, which means that any authservice connected to it will never
read stale data. Of course, this comes at a price; in most cases, even latency
between regions (and the regions we operate in are vastly separate) can cause
problems. As time passed by, we had a few outages related to the CockroachDB
cluster being unavailable. Most of these outages steemed from the fact that if a
node went down, the entire cluster became unavailable. We have figured out that
we don't necessarily need a strongly consistent database. In fact, we even tried
using CockroachDB as an eventually consistent database by exploiting the AS OF
SYSTEM TIME clause. Using this clause for reads would mean that the read request
would go to the nearest online node serving as a read replica
(https://www.cockroachlabs.com/docs/stable/follower-reads.html). Unfortunately,
this is a feature that requires an enterprise license, which is something we
don't want to buy for a case as simple as auth database. With this context in
mind, we went on a search for a better solution. The solution we preliminary
agreed on is an in-house solution. Most of the available solutions try to solve
much bigger problems than we here, so the complexity of the solution often shows
up on the infrastructural side of the service. We believe that it would be
easier to be experts in our own thing because it should be fairly
straightforward. An in-house solution would also allow the community to run auth
database in a cluster easier than it's now.

### Past experience and observations

Our experience influences the solution we want to agree on. Below are some key
observations we have made.

#### Observation #1: Does auth database need to be a NoSQL database?

There's no reason that auth database must be a SQL database. It's one table at
the moment, and we do simple queries on it only.

#### Observation #2: auth database can be eventually consistent

We don't need auth database to be strongly consistent because revocations happen
on the satellite side, and it's not straightforward to revoke/delete credentials
from auth database. The only way to delete the credential (from the user
perspective) is to set an expiration for the access grant, but we never
guaranteed it would be removed at this exact time point because a request with
that access grant would be denied by the satellite anyway.

### Requirements

#### Read latency

Read latency shouldn't be affected by cross-regional latency, so it should be in
the range of a couple of milliseconds.

#### Write latency

Write latency shouldn't be affected by cross-regional latency, so it should be
in the range of a couple of milliseconds.

#### Replication latency

Replication latency should be configurable, i.e., we should be able to control
how long it takes for a node to pull or push data to another node. Ideally, it
should be in the range of a couple of seconds.

#### Consistency and availability

Based on the previous observations, auth database can/should be eventually
consistent, and it's much more convenient to implement eventual consistency.

Any online authservice should be able to respond with data from the database,
even if other authservices/entire regions are down.

#### Load

It has been observed from metrics that the auth database doesn't do more than
around 1 request per second on average for both reads and writes. Occasionally,
this spikes to higher rates like 25 per second, but this happens very
infrequently.

## Design

### Definitions

#### Node

A unique deployment of authservice. Node has its own globally unique ID
(manually set or auto-generated).

#### Neighbour

A neighbour is a node the other node knows about through, e.g. placing the
neighbour's address in that node's configuration.

Nodes can also discover their neighbors automatically. One of the options is to
use a library for peer self-discovery like https://github.com/hashicorp/serf.

#### Local replica

Node's local, embedded into authservice database.

#### Replication log

Local replica's current state of the database that other nodes will replicate.

#### Replication chore/job/loop

A loop that each node runs to synchronize its replication log with neighbour
nodes.

### Data model

_In the snippets below, data types are Go's data types._

The following design will require two separate stores.

#### Record

```
record (
  // record data
  encryption_key_hash []byte
  created_at          time.Time
  public              bool

  // denormalized information from access grant
  satellite_address string
  macaroon_head     []byte
  expires_at        time.Time (optional)

  // sensitive data
  encrypted_secret_key   []byte
  encrypted_access_grant []byte

  // invalid tracking (both optional)
  invalid_reason string
  invalid_at     time.Time

  // state the record is in
  state State
)
```

`State` is an enum consisting of `Created`, `Invalidated` and `Deleted`.

The encryption key hash is the index and the SHA256 sum of the Access Key ID.
Since we version it, it won't be a problem to change the hashing function if
needed.

#### Replication log entry

```
replication_log_entry (
  authservice_id      string
  counter             int64
  encryption_key_hash []byte
  operation           State
)
```

### Supported operations

Operations we support will be the same that the authservice's KV interface
consists of right now.

### Replication algorithm

In this vector clock-based approach, every node maintains its own monotonic log
of operations (replication log) synced by its neighbours.

When a record is added, the node increments its global atomic counter and adds a
replication log entry with its node ID, the current state of the counter, given
encryption key hash and Created operation. Similarly, when a record is mutated,
e.g. invalidated, the node increments its global atomic counter and adds a
replication log entry with its node ID, the current state of the counter, given
encryption key hash and Invalidated operation. Any node can perform mutation of
any existing record.

Every node in the cluster will fetch from neighbour nodes portion of their
replication log that is later (based on the value of the counter, i.e. the
clock) than what they currently have for each of their neighbours. This means
that nodes can also return data for nodes that the node asking for data does not
know about.

Operations can be applied in any order to form the retrieval part of a local
replica and will always result in a consistent view of the database. This
ensures synchronization can be eventually-consistent.

This property is maintained by making sure that every modification of a specific
record is tied to the node ID from which mutation was requested. This means that
after the eventual synchronization of all replication logs, modification of a
specific record will not be overwritten on another node (as would be the case if
it was tied to the creator node ID).

Additionally, to maintain this property, a record can only mutate from Created
state to Invalidated/Deleted and from Invalidated to Deleted. Once the record is
in a subsequent state, it can never go back. Nodes apply operations following
these rules.

On any conflict on `created_at`, `expires_at`, `invalid_at, invalid_reason`
the algorithm should choose minimum of both of these. If `invalid_at` is
equal, it should choose `invalid_reason` that is lexicographically smaller.

### Deletes and pruning replication log

Deleting a record will transition it to the Deleted state and set a Time To Live
(TTL) for the corresponding record (and all operations in replication log
corresponding to that record) to a configurable value. After that time has
passed, this data will be garbage-collected.

### Out of sync nodes

These nodes that were offline for too long (the threshold should be the time it
takes to garbage-collect deleted records, as described above) and try to fetch
replication log from too far in time will receive an "out of sync" error. This
will be a signal for these nodes to start over, meaning deleting the replication
log and fetching everything from zero until they no longer get "out of sync"
responses (we will ensure configurable entries-per-response limit, hence why it
might not be able to send everything in one message).

### Adding new nodes to the cluster

Adding a new node will simply mean updating the list of nodes it knows about and
adding it to the list of nodes other nodes know about.

### Deleting nodes from the cluster

Since nodes keep a replication log of all nodes they have ever known about, it
won't be a problem to retire some nodes. Eventually, someone in charge will have
to delete the retired node from the list of nodes other nodes know about so that
the existing nodes won't complain they can't connect to the retired node.

### Backups

For backups, we will backup the local replicas to Storj DCS after every
specified interval in the background. We could compress it.

### Migration

We want to avoid downtime like lava. For migration that could be triggered by
specifying a configuration flag, we will instantiate a background job that moves
all data from CockroachDB to the new database and for every request, depending
on the request:

* PUT: save the record to the new database;
* GET:
  * check if the new database contains the requested record;
  * fallback to CockroachDB.

The deployment engineer would re-launch authservices after the migration job
completes.

## Rationale

An obvious alternate approach is to not leave CockroachDB. However, as with many
other solutions to this problem, they try to solve a much more general problem
than we need to, which often shows up on the infrastructural side of the
service. On the other hand, writing our solution requires time, effort and
making sure we don't have any critical issues when we roll out. Existing
solutions are, most of the time, already polished.

The benefit of the new database being embedded (which means we can easily spin
up a local, persistent instance that isn't an in-memory store) is another part
of the rationale in choosing to build our own thing. This also benefits Storj's
community (it will be much easier to run authservice in a cluster). On the other
hand, an embedded database means we have to provide the tooling, e.g. to query
the database ourselves.

### Pros and cons of leaving CockroachDB

The biggest advantage of leaving CockroachDB will be increased availability
(when one region goes down, only this region goes down). Another plus should be
decreased read/write latency and possibly a smaller database due to how our data
will be serialized, compressed and saved.

The biggest disadvantage will be that we will be on our own without CockroachDB.
It means no support whatsoever. The data will also not be instantly available in
all regions, and if we need to work with data in our own database, we won't be
able to query it as easily as it's possible with SQL without writing any tool of
our own. From the start, we might also be lacking metrics and nice dashboards
that allow us to monitor the cluster's health. CockroachDB has this out of the
box.

### Other available solutions

#### TiKV

Using TiKV might be possible, but it requires a significant infrastructural
effort to set up, and at this moment, we don't even have enough hardware to set
it up: https://tikv.org/docs/5.1/deploy/install/production/. TiKV is also
strongly consistent, which is a feature we don't need to work towards (if the PD
component goes down, we are in the same spot as with CockroachDB's node going
down in the current configuration).

#### etcd/Consul/ZooKeeper

Using etcd might be possible, but it does not scale after the database size of
several gigabytes: https://etcd.io/docs/v3.5/learning/why/. This is also the
case with Consul and ZooKeeper.

#### Postgres and its asynchronous replication.

Postgres supports asynchronous replication:
https://www.postgresql.org/docs/current/warm-standby.html.

However, given our past experience with Postgres and its failover mechanisms, we
found out it requires too much time to transition the leadership after the
primary server dies (the estimation we came up with is 2-3 minutes). Using a
multi-master configuration might be possible, but since it's not native, we have
been advised that many solutions have, e.g. serious consistency issues. Postgres
also does not have any out of the box monitoring.

## Implementation

For the underlying key-value DB on every node, we will use
[BadgerDB](https://github.com/dgraph-io/badger). For replication-related
communication, we will use DRPC.

The implementation will avoid comparisons that would lead to comparing time on
two nodes, but the allowed wall clock drift should be the skew that allows ntpd
to still function.

### Data model implementation

#### Record

```protobuf
message Record {
  // record data
  Timestamp created_at = 1;
  bool      public = 2;

  // denormalized information from access grant
  string     satellite_address = 3;
  bytes      macaroon_head = 4;
  Timestamp  expires_at = 5;

  // sensitive data
  bytes encrypted_secret_key = 6;
  bytes encrypted_access_grant = 7;

  // invalid tracking
  string     invalid_reason = 8;
  Timestamp  invalid_at = 9;

  enum State {
    CREATED = 0;
    INVALIDATED = 1;
    DELETED = 2;
  }

  // synchronization-related data
  State state = 10;
}
```

Records will be serialized and saved in the Protocol Buffers binary format.

#### Replication log entry

A replication log entry can be key-only and may take the following form:

`authservice_id/counter/encryption_key_hash/operation`

An entry can also be a protobuf saved under `authservice_id/counter`.

### KV interface:

Currently, the KV interface that serves as an interface for the storage backend
of authservice is:

```go
// KV is an abstract key/value store of KeyHash to Records.
type KV interface {
    // Put stores the record in the key/value store.
    // It is an error if the key already exists.
    Put(ctx context.Context, keyHash KeyHash, record *Record) (err error)

    // Get retrieves the record from the key/value store.
    // It returns nil if the key does not exist.
    // If the record is invalid, the error contains why.
    Get(ctx context.Context, keyHash KeyHash) (record *Record, err error)

    // Delete removes the record from the key/value store.
    // It is not an error if the key does not exist.
    Delete(ctx context.Context, keyHash KeyHash) error

    // DeleteUnused deletes expired and invalid records from the key/value store
    // and returns any error encountered.
    //
    // Batch deletion and usage of asOfSystemInterval, selectSize and deleteSize
    // parameters depends on the implementation.
    DeleteUnused(ctx context.Context, asOfSystemInterval time.Duration, selectSize, deleteSize int) (count, rounds int64, deletesPerHead map[string]int64, err error)

    // Invalidate causes the record to become invalid.
    // It is not an error if the key does not exist.
    // It does not update the invalid reason if the record is already invalid.
    Invalidate(ctx context.Context, keyHash KeyHash, reason string) error

    // Ping attempts to do a DB roundtrip. If it can't it will return an
    // error.
    Ping(ctx context.Context) error

    // Close closes the database.
    Close() error
}
```

We will discuss the implementation of its methods in the dedicated subsections.

Whenever a corresponding replication log entry must be created, the node shall
use its node ID for filling out `authservice_id` and the highest counter value
it has for `counter`.

#### Put

We will use BadgerDB's API to write records to the local replica
(https://dgraph.io/docs/badger/get-started/#using-key-value-pairs).

The implementation will do the following (in a transaction):

1. Save record under `encryption_key_hash`
2. Create a corresponding replication log entry with the `CREATED` operation

#### Get

We will use BadgerDB's API to retrieve records from the local replica
(https://dgraph.io/docs/badger/get-started/#using-key-value-pairs).

The implementation will do the following:

1. Retrieve record
2. Check if the record is valid and is not in a temporary `DELETED` state

#### Delete

The implementation will do the following (in a transaction):

1. Retrieve record
2. Check whether the record is not already in a temporary `DELETED` state
3. Modify the state of the record to `DELETED`
4. Create a corresponding replication log entry with the `DELETED` operation
5. Both record and corresponding replication log entries should now have TTL
  1. TTL will be the same as after which offline nodes are out of sync
  2. TTL must not be greater than the already existing TTL

#### DeleteUnused

Deleting expired records will be "by design", meaning that records that already
come with an expiration date will have TTL set to that time (as well as their
corresponding replication log entries). Nodes replicating these records will
need to set TTL for them as well (and for their corresponding replication log
entries).

#### Invalidate

The implementation will do the following (in a transaction):

1. Retrieve record
2. Check whether the record is not already in the `INVALIDATED`/`DELETED` state
3. Modify the state of the record to `INVALIDATED`
4. Create a corresponding replication log entry with the `INVALIDATED` operation

#### Ping

Since BadgerDB will be embedded in authservice, it does not support any kind of
Ping operations, so this method would always return a nil error. We can also
implement adding a test record and deleting it for the Ping operation to ensure
things work correctly.

#### Close

Invoke https://pkg.go.dev/github.com/dgraph-io/badger/v3#DB.Close and close the
replication chore.

### Replication chore

#### Definitions for the replication chore implementation

```protobuf
message ReplicationRequestEntry {
  string authservice_id = 1;
  uint64 counter = 2;
}

message ReplicationRequest {
  string   auth_token = 1;
  repeated ReplicationRequestEntry entries = 2;
}

message ReplicationResponseEntry {
  string authservice_id = 1;
  uint64 counter = 2;
  bytes  encryption_key_hash = 3;
  Record record = 4;
}

message ReplicationResponse {
  repeated ReplicationResponseEntry entries = 1;
}

service ReplicationService {
  rpc Replicate(ReplicationRequest) returns (ReplicationResponse);
}
```

#### Replicate implementation

Every node will run a replication loop, meaning calling Replicate on all nodes
the node knows about every fixed interval.

The node that calls replicate will gather the highest available counters for all
nodes it knows about from its replication log and send them in the request.

The node that responds to the request will gather records and replication log
entries above the counters from the request and send them in batch. The batch
should be configurable, e.g. up to 10000 records.

The node receiving the batch will add received replication log entries and
records to its local replica. Records will be mutated according to the rules
laid out in the Design/Replication algorithm section. If the record/log entry
has TTL, it will be added as well. The `created_at` field will be updated and
filled out with the current time of the node receiving the response.

No log entries can be missed. If syncing node asks for entries starting from,
e.g. 3 and 3 is no longer available, and the next available record is 4 or
above, then the node will be considered out of sync (see _Handling out of sync
nodes_).

Nodes will authenticate with each other using an auth token sent with requests.

##### Handling out of sync nodes

Whenever a new node is added to the cluster or an existing node is added after a
long time, it will also send its counter values to its neighbours. When the
responding node does not find a corresponding log entry or the entry is too far
in the past (based on its own clock and the `created_at` field of the record),
it will respond with an "out of sync" error. In this case, the out of sync node
will lock its read, writes and replication and begin to sync. It will create a
new local replica and ask for data for all nodes it knows about from counters =
0 until the response no longer begins with the "out of sync" status code. After
that, it will unlock reads, writes and replication and begin to operate
normally.

## Wrapup

This blueprint will be archived by Artur Wolff and Sean Harvey.

It will be a good idea to write a document on KV backends authservice supports,
why we have them and which is best for a specific environment.

## Open issues

### Partial implementation

Based on the experience of the usage of authservice's API, it might be a good
idea to implement just Put, Get, DeleteUnused and the replication mechanism for
a start. Deletion/invalidation/modifying anything in the record could be handled
by an external tool that connects to all nodes if needed.

### DeleteUnused

For some weird reason, when I (Artur) implemented DeleteUnused for other
backends, I chose to also delete invalidated records. With the current approach
to records deletion, this might be much more tricky (or unelegant) to match this
behaviour. Obviously, I'm in favour of not following this detail because I
consider this bad behaviour. I believe we shouldn't delete any records that
aren't expired, i.e. we shouldn't delete records that still mean something.

### Are we safe from human error?

Even if we let someone put up a cluster with two same node IDs (e.g. someone
copied the same authservice ID into two places) and didn't implement any
preflight check, this shouldn't cause a catastrophic failure. One way to avoid
this is to always generate an ID for authservice at the start of a particular
instance.

### The durability of writes

One way to ensure that we never lose a record before it gets replicated to other
nodes would be to write it to, e.g., two nodes synchronously. This requires the
record's initial recipient node to choose second or more nodes to force them to
pull necessary information like in the standard replication process, but this
time synchronously.
