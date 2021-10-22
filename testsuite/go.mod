module storj.io/gateway-mt/testsuite

go 1.14

replace storj.io/gateway-mt => ../

require (
	github.com/aws/aws-sdk-go v1.36.15
	github.com/minio/minio-go/v7 v7.0.6
	github.com/spf13/pflag v1.0.5
	github.com/stretchr/testify v1.7.0
	github.com/zeebo/errs v1.2.2
	go.uber.org/zap v1.16.0
	storj.io/common v0.0.0-20211006105453-d3fff091f9d2
	storj.io/drpc v0.0.26
	storj.io/gateway-mt v0.0.0-00010101000000-000000000000
	storj.io/private v0.0.0-20210810102517-434aeab3f17d
	storj.io/storj v0.12.1-0.20210819172313-a5371353bf62
)

replace (
	storj.io/common => ../../common
)
