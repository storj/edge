module storj.io/gateway-mt/testsuite

go 1.14

replace storj.io/gateway-mt => ../

require (
	github.com/aws/aws-sdk-go v1.36.15
	github.com/btcsuite/btcutil v1.0.3-0.20201208143702-a53e38424cce
	github.com/storj/minio v0.0.0-20210219144617-4237bd332274
	github.com/stretchr/testify v1.6.1
	github.com/zeebo/errs v1.2.2
	go.uber.org/zap v1.16.0
	storj.io/common v0.0.0-20210218090211-2ecbfc1f705b
	storj.io/gateway-mt v0.0.0-00010101000000-000000000000
	storj.io/storj v0.12.1-0.20210219134134-8b9da01817dc
	storj.io/uplink v1.4.6-0.20210219140335-667f093f4a3a
)
