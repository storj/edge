module storj.io/gateway-mt/testsuite

go 1.14

replace storj.io/gateway-mt => ../

require (
	github.com/aws/aws-sdk-go v1.36.15
	github.com/btcsuite/btcutil v1.0.3-0.20201208143702-a53e38424cce
	github.com/storj/minio v0.0.0-20210330111527-04e6dc87c349
	github.com/stretchr/testify v1.7.0
	github.com/zeebo/errs v1.2.2
	go.uber.org/zap v1.16.0
	storj.io/common v0.0.0-20210325225810-6cd9934a276a
	storj.io/gateway-mt v0.0.0-00010101000000-000000000000
	storj.io/storj v0.12.1-0.20210330203205-86c41790ce6b
	storj.io/uplink v1.4.6-0.20210330101846-63e323b65e90
)
