module storj.io/stargate/testsuite

go 1.14

replace storj.io/stargate => ../

require (
	github.com/btcsuite/btcutil v1.0.2
	github.com/storj/minio v0.0.0-20201118180608-b7036f0538ab
	github.com/stretchr/testify v1.6.1
	github.com/zeebo/errs v1.2.2
	go.uber.org/zap v1.16.0
	storj.io/common v0.0.0-20201030140758-31112c1cc750
	storj.io/stargate v0.0.0-00010101000000-000000000000
	storj.io/storj v0.12.1-0.20201013144504-830817ec0dde
	storj.io/uplink v1.3.2-0.20201104145754-2f6dfd29a96c
)
