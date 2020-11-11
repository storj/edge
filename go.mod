module storj.io/stargate

go 1.13

require (
	github.com/btcsuite/btcutil v1.0.2
	github.com/calebcase/tmpfile v1.0.2 // indirect
	github.com/jackc/pgconn v1.7.0
	github.com/jackc/pgx/v4 v4.9.0
	github.com/mattn/go-sqlite3 v1.14.4
	github.com/minio/cli v1.22.0
	github.com/minio/minio v0.0.0-20200808024306-2a9819aff876
	github.com/minio/minio-go/v6 v6.0.58-0.20200612001654-a57fec8037ec
	github.com/shirou/gopsutil v3.20.10+incompatible // indirect
	github.com/spacemonkeygo/monkit/v3 v3.0.7
	github.com/spf13/cobra v0.0.6
	github.com/spf13/pflag v1.0.5
	github.com/stretchr/testify v1.5.1
	github.com/zeebo/errs v1.2.2
	go.uber.org/zap v1.15.0
	golang.org/x/crypto v0.0.0-20200820211705-5c72a883971a
	golang.org/x/sys v0.0.0-20201014080544-cc95f250f6bc // indirect
	google.golang.org/api v0.20.0 // indirect
	storj.io/common v0.0.0-20201030140758-31112c1cc750
	storj.io/private v0.0.0-20201026143115-bc926bfa3bca
	storj.io/uplink v1.3.2-0.20201104145754-2f6dfd29a96c
)

replace github.com/minio/minio => github.com/storj/minio v0.0.0-20201110204916-623e6095d650
