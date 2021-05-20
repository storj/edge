module storj.io/gateway-mt/testsuite

go 1.14

replace storj.io/gateway-mt => ../

require (
	github.com/aws/aws-sdk-go v1.36.15
	github.com/btcsuite/btcutil v1.0.3-0.20201208143702-a53e38424cce
	github.com/storj/minio v0.0.0-20210507172446-1458d31a273b
	github.com/stretchr/testify v1.7.0
	github.com/zeebo/errs v1.2.2
	go.uber.org/zap v1.16.0
	storj.io/common v0.0.0-20210526153251-5d1c183ca6ac
	storj.io/gateway-mt v0.0.0-00010101000000-000000000000
	storj.io/storj v1.30.3
	storj.io/uplink v1.5.0-rc.1.0.20210527065710-eb24c87c9e9e
)
