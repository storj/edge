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
	storj.io/common v0.0.0-20210413145726-6095a5c22253
	storj.io/gateway-mt v0.0.0-00010101000000-000000000000
	storj.io/storj v0.12.1-0.20210414215329-bd36a41a9ebe
	storj.io/uplink v1.4.6-0.20210413225639-818b428249a1
)
