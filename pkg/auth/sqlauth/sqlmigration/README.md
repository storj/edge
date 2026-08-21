# sqlmigration

The sqlmigration backend migrates authservice records from one SQL database to
another without downtime, e.g. moving off a managed instance onto a self-hosted
one.

Select it with `--kv-backend='sqlmigration://'`. The source is the database
authservice already points at (`--sql.url`), and the destination is the one
being migrated to (`--sql-migration-destination.url`). Both take the full set
of `sqlauth` connection options.

In this mode authservice writes to both databases on Put, and reads the
destination first with a fallback to the source on Get. `authservice run
migration` backfills the records the source already has into the destination.

## Configuration

|          **Parameter**          |                        **Description**                        | **Default value** |
|:-------------------------------:|:-------------------------------------------------------------:|:-----------------:|
| `sql-migration-destination.url` |            Destination SQL database connection URL            |                   |
|   `sql-migration-concurrency`   |      Number of parallel key-range workers in the backfill     |        `16`       |
|    `sql-migration-batch-size`   |            Rows per bulk-copy batch in the backfill           |       `5000`      |

The backfill splits the key-hash space into `sql-migration-concurrency`
partitions and runs them all at once, so raising it is the way to make a
backfill finish sooner. Increasing `sql-migration-batch-size` has less effect:
the read side pages at a fixed 1000 rows, so past a few thousand the per-batch
round trips are no longer what dominates.

### Connection pool sizing

Each backfill worker pins one destination connection for the whole run and
draws a source connection whenever it scans a page, so
`sql-migration-concurrency` should stay comfortably below the smaller of
`sql.max-open-conns` and `sql-migration-destination.max-open-conns`, leaving
headroom for the connections that serve traffic. Get reads the destination
first, Put writes it on every registration, and HealthCheck pings it, so a
backfill that consumes the destination pool degrades serving even while it
succeeds.

This is not enforced. Setting concurrency at or above a pool's size does not
error: the surplus workers block in the pool until earlier partitions finish
and release their connections, and past that point serving requests queue
behind them, with no log line explaining the stall.

With the default 25-connection pools, the default concurrency of 16 already
takes most of the destination pool for the duration of the backfill. Prefer
running the backfill as a standalone job (below), where it has the pools to
itself, and size the pools up before raising concurrency.

## Recommended rollout

The backfill is not a cheap schema check. It scans the whole source table and
blocks its caller until it finishes, which on a large table can take hours.

1. Run the backfill once as a standalone, non-production-facing job:
   `authservice run migration` with `--kv-backend='sqlmigration://'` and both
   database URLs set. This creates the destination schema and copies existing
   records across. It is idempotent, so it can be re-run after a partial
   failure.
2. Once it completes, restart the serving replicas with
   `--kv-backend='sqlmigration://'`, so they dual-write and serve from the
   destination with a source fallback.
3. Watch `as_sqlmigration_destination_miss` (see Metrics). Once it is 0, every
   record being served is coming from the destination.
4. Cut over by switching `--kv-backend='sql://'` with `--sql.url` pointed at
   the destination, and drop the migration parameters.

Do not pair `--migration` with `sqlmigration://` on a replica that also serves
traffic. `--migration` runs the same backfill synchronously before the server
starts, so startup, health checks, and any rolling deploy block for its whole
duration, and every replica configured that way independently repeats the work
against both databases.

## Admin mutations during a migration

For as long as the migration window is open, which includes the whole
standalone backfill job in step 1, every invalidate, unpublish, and delete
must be applied to **both** databases.

The backfill only inserts. Once a key has been copied into the destination, no
later run updates or removes it there, and reads prefer the destination, so a
mutation applied to the source alone is lost at cutover: an invalidated key
keeps authenticating, an unpublished record stays public, and a deleted record
comes back.

authservice does this for records written through it. Admin tooling has to do
it too: run [`authservice-admin`](../../../../cmd/authservice-admin/README.md)
with both `--storage.sql.url` and
`--storage.sql-migration-destination.url` set for the duration of the window,
never pointed at the source alone.

Doing that is necessary but not sufficient while the backfill of step 1 is
still running. A worker holds up to `sql-migration-batch-size` records in
memory between reading them from the source and writing them to the
destination, and that write does not overwrite what is already there, so a
record read into a batch before a mutation is written after it in its
pre-mutation state. Mutations issued during the backfill must therefore be
re-applied once it completes. Mutations issued after it completes are covered
by the flags alone.

## Metrics

|                 **Event**                |                          **Meaning**                          |
|:----------------------------------------:|:-------------------------------------------------------------:|
|      `as_sqlmigration_destination_hit`   |          A Get was answered by the destination         |
|      `as_sqlmigration_destination_miss`  |    A Get fell back to the source and found the record  |
|   `as_sqlmigration_destination_put_err`  |        A Put wrote the source but failed on the destination   |
| `as_sqlmigration_destination_put_duplicate` | A Put found the key already in the destination (see below) |

A steady `as_sqlmigration_destination_miss` rate is expected while the backfill
is still running and should fall to 0 once it completes; use it as the signal
for step 3 above.

`as_sqlmigration_destination_put_duplicate` is normally benign: a
concurrently-running backfill can copy a record into the destination between a
Put's source and destination writes, in which case the record is present either
way. It also covers the case where the destination holds a *different* record
under that key hash, which authservice cannot distinguish from the benign one,
so a sustained rate outside a running backfill is worth investigating.
