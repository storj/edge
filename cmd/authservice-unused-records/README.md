cmd/authservice-unused-records
==============================

This tool is intended to be used by the prod owner to perform deletion of
records that have no expiration date in the auth service database but are
confirmed for deletion by the customer (hence the existence of the
`macaroon-head` flag). Please use `--dry-run` first to get the report and
confirm the number of records to delete.

## Usage

### Getting the report (please do this first!)

```sh
$ authservice-unused-records --as-of-system-interval -5s --authservicedb 'postgres://...' --dry-run --macaroon-head 68747470733a2f2f7777772e796f75747562652e636f6d2f77617463683f763d6451773477395767586351 --select-size 10000
```

### Deleting the data

```sh
$ authservice-unused-records --as-of-system-interval -5s --authservicedb 'postgres://...' --delete-size 1000 --macaroon-head 68747470733a2f2f7777772e796f75747562652e636f6d2f77617463683f763d6451773477395767586351 --select-size 10000
```
