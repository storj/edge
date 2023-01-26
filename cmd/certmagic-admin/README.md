# certmagic-admin

This is a tool used to interact directly with certificates stored by CertMagic.

## Install

```console
$ go install storj.io/gateway-mt/cmd/certmagic-admin
```

## Prerequisites

To run any commands you will need:
* the certificate storage bucket name
* the path to a service account key file with permissions to use Google's Cloud Storage

To run obtain, renew, or revoke you also need:
* permissions for the Google Public CA and Cloud DNS
* the project name where the DNS zone exists
* the ACME accounts email address

## Usage


Example command:

```console
$ certmagic-admin --keyfile key.json --bucket certmagic_bucket cert show www.example.com
```

Debug logging can be enabled by using the `--log.debug` flag.

### Commands

#### List Certificates

Lists all the certificates in storage grouped by issuer.

```console
$ certmagic-admin --keyfile <keyfile> --bucket <bucket_name> cert list
```

#### Show Certificate

Show prints a certificate in storage. If there are multiple certificates with the same name the most recent is printed. You must specify `--staging` to see a certificate from a staging issuer.

```console
$ certmagic-admin --keyfile <keyfile> --bucket <bucket_name> cert show [--staging] <name>
```

#### Obtain Certificate

Obtains and stores a certificate for a domain. If the certificate is already in storage this command has no effect.  Wildcard certificates are allowed. Certificates with multiple SANs are not supported.

```console
$ certmagic-admin --keyfile <keyfile> --bucket <bucket_name> cert obtain --dnsproject <project> --email <email> [--staging] [--gpublicca] [--letsencrypt] <name>
```

#### Renew Certificate

Renew and store a certificate. Specify `--force` to renew a certificate that is not close to expiring.

```console
$ certmagic-admin --keyfile <keyfile> --bucket <bucket_name> cert renew --dnsproject <project> --email <email> [--staging] [--force] <name>
```

#### Revoke certificate

Revoke a certificate and delete it from storage. Disable the issuer that did not issue the certificate being revoked with `--gpublicca=false` or `--letsencrypt=false`.  The email and ACME account must be the same as the one that issued the certificate. Valid reasons are: unspecified, keyCompromise, affiliationChanged, superseded, cessationOfOperation, priviledgeWithdrawn, aACompromise. A `certificate revoked, but unable to fully clean up assets from issuer` error message is expected and can be safely ignored.

```console
$ certmagic-admin --keyfile <keyfile> --bucket <bucket_name> cert revoke --email <email> [--staging] [--gpublicca] [--letsencrypt] <name> <reason>
```
