module storj.io/gateway-mt

go 1.13

require (
	github.com/aws/aws-sdk-go-v2 v1.1.0
	github.com/gorilla/mux v1.8.0
	github.com/jackc/pgconn v1.8.0
	github.com/jackc/pgx/v4 v4.10.1
	github.com/minio/minio-go/v6 v6.0.58-0.20200612001654-a57fec8037ec
	github.com/spacemonkeygo/errors v0.0.0-20201030155909-2f5f890dbc62 // indirect
	github.com/spacemonkeygo/monkit/v3 v3.0.11-0.20210401165229-87c388352ef7
	github.com/spf13/cobra v0.0.6
	github.com/spf13/pflag v1.0.5
	github.com/storj/minio v0.0.0-20210507172446-1458d31a273b
	github.com/stretchr/testify v1.6.1
	github.com/zeebo/errs v1.2.2
	go.uber.org/zap v1.16.0
	golang.org/x/crypto v0.0.0-20201221181555-eec23a3978ad
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	gopkg.in/webhelp.v1 v1.0.0-20170530084242-3f30213e4c49
	storj.io/common v0.0.0-20210412024514-5bcb1fff421e
	storj.io/private v0.0.0-20210403210935-5fd57695864c
	storj.io/uplink v1.4.7-0.20210422134834-21140a50fee2
)
