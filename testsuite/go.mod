module storj.io/gateway-mt/testsuite

go 1.14

replace storj.io/gateway-mt => ../

require (
	github.com/aws/aws-sdk-go v1.36.15
	github.com/btcsuite/btcutil v1.0.3-0.20201208143702-a53e38424cce
	github.com/minio/minio v0.0.0-20201216013454-c606c7632365
	github.com/minio/minio-go/v7 v7.0.6
	github.com/stretchr/testify v1.7.0
	github.com/zeebo/errs v1.2.2
	go.uber.org/zap v1.16.0
	storj.io/common v0.0.0-20210916151047-6aaeb34bb916
	storj.io/gateway-mt v0.0.0-00010101000000-000000000000
	storj.io/storj v0.12.1-0.20210819172313-a5371353bf62
	storj.io/uplink v1.6.0
)

replace github.com/minio/minio => storj.io/minio v0.0.0-20210914060719-27c1b4bf0b74
