module storj.io/gateway-mt/testsuite

go 1.14

replace storj.io/gateway-mt => ../

require (
	github.com/aws/aws-sdk-go v1.36.15
	github.com/minio/minio-go/v7 v7.0.6
	github.com/stretchr/testify v1.7.0
	github.com/zeebo/errs v1.2.2
	go.uber.org/zap v1.16.0
	storj.io/common v0.0.0-20210922161202-47f5ba40a543
	storj.io/gateway-mt v0.0.0-00010101000000-000000000000
	storj.io/storj v0.12.1-0.20210819172313-a5371353bf62
)

replace github.com/minio/minio => storj.io/minio v0.0.0-20210914060719-27c1b4bf0b74
