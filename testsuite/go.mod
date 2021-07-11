module storj.io/gateway-mt/testsuite

go 1.14

replace storj.io/gateway-mt => ../

require (
	github.com/aws/aws-sdk-go v1.36.15
	github.com/btcsuite/btcutil v1.0.3-0.20201208143702-a53e38424cce
	github.com/storj/minio v0.0.0-20210709114951-cf559f5e26d5
	github.com/stretchr/testify v1.7.0
	github.com/zeebo/errs v1.2.2
	go.uber.org/zap v1.16.0
	storj.io/common v0.0.0-20210708125041-4882a3ae3eda
	storj.io/gateway-mt v0.0.0-00010101000000-000000000000
	storj.io/storj v1.34.0-rc
	storj.io/uplink v1.5.0-rc.1.0.20210708154526-f5ca59991bd8
)
