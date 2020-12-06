module storj.io/gateway-mt/testsuite

go 1.14

replace storj.io/gateway-mt => ../

require (
	github.com/btcsuite/btcutil v1.0.3-0.20201124182144-4031bdc69ded
	github.com/storj/minio v0.0.0-20201123173841-6fdac6dbc542
	github.com/stretchr/testify v1.6.1
	github.com/zeebo/errs v1.2.2
	go.uber.org/zap v1.16.0
	storj.io/common v0.0.0-20201207172416-78f4e59925c3
	storj.io/gateway-mt v0.0.0-00010101000000-000000000000
	storj.io/storj v0.12.1-0.20201207134547-cdeea1c9991b
	storj.io/uplink v1.4.2-0.20201207200902-096b244adcb2
)
