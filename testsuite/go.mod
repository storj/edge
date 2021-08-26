module storj.io/gateway-mt/testsuite

go 1.14

replace storj.io/gateway-mt => ../

require (
	github.com/aws/aws-sdk-go v1.36.15
	github.com/btcsuite/btcutil v1.0.3-0.20201208143702-a53e38424cce
	github.com/minio/minio v0.0.0-00010101000000-000000000000
	github.com/minio/minio-go/v7 v7.0.6
	github.com/stretchr/testify v1.7.0
	github.com/zeebo/errs v1.2.2
	go.uber.org/zap v1.16.0
	storj.io/common v0.0.0-20210826213913-a78b0b6a12f3
	storj.io/gateway-mt v0.0.0-00010101000000-000000000000
	storj.io/storj v0.12.1-0.20210819172313-a5371353bf62
	storj.io/uplink v1.5.0-rc.1.0.20210827115050-6827e2032248
)

replace github.com/minio/minio => storj.io/minio v0.0.0-20210819113254-ef95e15300a2
