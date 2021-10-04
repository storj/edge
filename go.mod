module storj.io/gateway-mt

go 1.13

require (
	github.com/btcsuite/btcutil v1.0.3-0.20201208143702-a53e38424cce
	github.com/gorilla/mux v1.8.0
	github.com/jackc/pgconn v1.10.0
	github.com/jackc/pgx/v4 v4.13.0
	github.com/miekg/dns v1.1.35
	github.com/minio/minio v0.0.0-20201216013454-c606c7632365
	github.com/minio/minio-go/v7 v7.0.6
	github.com/oschwald/maxminddb-golang v1.7.0
	github.com/rs/cors v1.7.0
	github.com/spacemonkeygo/errors v0.0.0-20201030155909-2f5f890dbc62 // indirect
	github.com/spacemonkeygo/monkit/v3 v3.0.15
	github.com/spf13/cobra v1.1.3
	github.com/spf13/pflag v1.0.5
	github.com/stretchr/testify v1.7.0
	github.com/zeebo/errs v1.2.2
	go.uber.org/zap v1.16.0
	golang.org/x/crypto v0.0.0-20210817164053-32db794688a5
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	gopkg.in/webhelp.v1 v1.0.0-20170530084242-3f30213e4c49
	storj.io/common v0.0.0-20210916151047-6aaeb34bb916
	storj.io/dotworld v0.0.0-20210324183515-0d11aeccd840
	storj.io/drpc v0.0.26
	storj.io/gateway v1.3.1-0.20211003223318-bdc1165baf61
	storj.io/private v0.0.0-20210810102517-434aeab3f17d
	storj.io/uplink v1.6.0
)

replace github.com/minio/minio => storj.io/minio v0.0.0-20210914060719-27c1b4bf0b74
