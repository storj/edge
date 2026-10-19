module storj.io/edge

go 1.26.0

require (
	github.com/aws/aws-sdk-go-v2 v1.43.0
	github.com/aws/aws-sdk-go-v2/config v1.31.10
	github.com/aws/aws-sdk-go-v2/credentials v1.18.14
	github.com/aws/aws-sdk-go-v2/service/s3 v1.106.0
	github.com/caddyserver/certmagic v0.25.3
	github.com/fatih/color v1.19.0
	github.com/google/go-cmp v0.7.0
	github.com/gorilla/mux v1.8.0
	github.com/grantae/certinfo v0.0.0-20170412194111-59d56a35515b
	github.com/jackc/pgx/v5 v5.10.0
	github.com/libdns/googleclouddns v1.2.0
	github.com/libdns/route53 v1.6.2
	github.com/mholt/acmez v1.2.0
	github.com/miekg/dns v1.1.72
	github.com/minio/cli v1.22.0
	github.com/minio/minio-go/v7 v7.3.0
	github.com/oschwald/maxminddb-golang v1.12.0
	github.com/outcaste-io/badger/v3 v3.2202.1-0.20220426173331-b25bc764af0d
	github.com/pires/go-proxyproto v0.7.0
	github.com/rs/cors v1.7.0
	github.com/spacemonkeygo/monkit/v3 v3.0.25-0.20251022131615-eb24eb109368
	github.com/spf13/cobra v1.10.2
	github.com/spf13/pflag v1.0.10
	github.com/stretchr/testify v1.11.1
	github.com/zeebo/clingy v0.0.0-20230602044025-906be850f10d
	github.com/zeebo/errs v1.4.0
	go.opentelemetry.io/otel v1.42.0
	go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp v0.18.0
	go.opentelemetry.io/otel/log v0.18.0
	go.opentelemetry.io/otel/sdk v1.42.0
	go.opentelemetry.io/otel/sdk/log v0.18.0
	go.uber.org/zap v1.28.0
	golang.org/x/net v0.59.0
	golang.org/x/oauth2 v0.36.0
	golang.org/x/sync v0.23.0
	google.golang.org/protobuf v1.36.12
	gopkg.in/webhelp.v1 v1.0.0-20170530084242-3f30213e4c49
	storj.io/common v0.0.0-20261009084351-793a367e9857
	storj.io/dotworld v0.0.0-20210324183515-0d11aeccd840
	storj.io/drpc v1.0.0
	storj.io/eventkit v0.0.0-20260707062648-170ec15e6f3f
	storj.io/gateway v1.11.1-0.20261019213828-020b2060ddd1
	storj.io/minio v0.0.0-20261019204001-103c23ba7578
	storj.io/uplink v1.14.6-0.20261015224055-4d6dc3c40b70
	storj.io/zipper v0.0.0-20220124122551-2ac2d53a46f6
)

require (
	cloud.google.com/go v0.123.0 // indirect
	cloud.google.com/go/auth v0.19.0 // indirect
	cloud.google.com/go/auth/oauth2adapt v0.2.8 // indirect
	cloud.google.com/go/bigquery v1.74.0 // indirect
	cloud.google.com/go/compute/metadata v0.9.0 // indirect
	cloud.google.com/go/iam v1.6.0 // indirect
	git.apache.org/thrift.git v0.13.0 // indirect
	github.com/Azure/go-ntlmssp v0.0.0-20200615164410-66371956d46c // indirect
	github.com/Shopify/sarama v1.27.2 // indirect
	github.com/VividCortex/ewma v1.2.0 // indirect
	github.com/alecthomas/participle v0.2.1 // indirect
	github.com/amwolff/awsig v0.0.0-20260427205242-5ad7e9e1912b // indirect
	github.com/apache/arrow/go/v15 v15.0.2 // indirect
	github.com/apache/thrift v0.17.0 // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.14 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.18.8 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.31 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.31 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.3 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.4.32 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.13 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.9.24 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.31 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.19.32 // indirect
	github.com/aws/aws-sdk-go-v2/service/route53 v1.58.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.29.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.35.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.38.5 // indirect
	github.com/aws/smithy-go v1.27.3 // indirect
	github.com/bcicen/jstream v1.0.1 // indirect
	github.com/beevik/ntp v0.3.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/caddyserver/zerossl v0.1.5 // indirect
	github.com/calebcase/tmpfile v1.0.3 // indirect
	github.com/cenkalti/backoff/v5 v5.0.3 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cheggaaa/pb v1.0.29 // indirect
	github.com/clipperhouse/uax29/v2 v2.7.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/dchest/siphash v1.2.3 // indirect
	github.com/djherbis/atime v1.0.0 // indirect
	github.com/dswarbrick/smart v0.0.0-20190505152634-909a45200d6d // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/eapache/go-resiliency v1.2.0 // indirect
	github.com/eapache/go-xerial-snappy v0.0.0-20180814174437-776d5712da21 // indirect
	github.com/eapache/queue v1.1.0 // indirect
	github.com/ebitengine/purego v0.10.2 // indirect
	github.com/eclipse/paho.mqtt.golang v1.5.1 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/flynn/noise v1.1.0 // indirect
	github.com/fsnotify/fsnotify v1.9.0 // indirect
	github.com/go-asn1-ber/asn1-ber v1.5.1 // indirect
	github.com/go-ldap/ldap/v3 v3.2.4 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/go-sql-driver/mysql v1.5.0 // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/goccy/go-json v0.10.2 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang-jwt/jwt/v4 v4.5.2 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/gomodule/redigo v1.8.3 // indirect
	github.com/google/flatbuffers v24.3.25+incompatible // indirect
	github.com/google/gopacket v1.1.19 // indirect
	github.com/google/pprof v0.0.0-20260604005048-7023385849c0 // indirect
	github.com/google/s2a-go v0.1.9 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.14 // indirect
	github.com/googleapis/gax-go/v2 v2.21.0 // indirect
	github.com/gorilla/handlers v1.5.1 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.28.0 // indirect
	github.com/hashicorp/go-uuid v1.0.2 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/jcmturner/gofork v1.0.0 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/jtolds/tracetagger/v2 v2.0.0-rc5 // indirect
	github.com/jtolio/crawlspace v0.0.0-20240521193440-69abbbe5a93f // indirect
	github.com/jtolio/crawlspace/tools v0.0.0-20240521193440-69abbbe5a93f // indirect
	github.com/jtolio/noiseconn v0.0.0-20231127013910-f6d9ecbf1de7 // indirect
	github.com/klauspost/compress v1.19.2 // indirect
	github.com/klauspost/cpuid/v2 v2.4.0 // indirect
	github.com/klauspost/crc32 v1.3.0 // indirect
	github.com/klauspost/pgzip v1.2.5 // indirect
	github.com/klauspost/readahead v1.3.1 // indirect
	github.com/klauspost/reedsolomon v1.9.11 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/lib/pq v1.10.2 // indirect
	github.com/libdns/libdns v1.1.1 // indirect
	github.com/lufia/plan9stats v0.0.0-20211012122336-39d0f177ccd0 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mattn/go-runewidth v0.0.23 // indirect
	github.com/mholt/acmez/v3 v3.1.6 // indirect
	github.com/minio/crc64nvme v1.1.1 // indirect
	github.com/minio/highwayhash v1.0.4 // indirect
	github.com/minio/md5-simd v1.1.2 // indirect
	github.com/minio/selfupdate v0.3.1 // indirect
	github.com/minio/sha256-simd v1.0.0 // indirect
	github.com/minio/simdjson-go v0.2.1 // indirect
	github.com/minio/sio v0.2.1 // indirect
	github.com/montanaflynn/stats v0.5.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/nats-io/nats.go v1.31.0 // indirect
	github.com/nats-io/nkeys v0.4.6 // indirect
	github.com/nats-io/nuid v1.0.1 // indirect
	github.com/nats-io/stan.go v0.8.3 // indirect
	github.com/ncw/directio v1.0.5 // indirect
	github.com/nsqio/go-nsq v1.0.8 // indirect
	github.com/olivere/elastic/v7 v7.0.22 // indirect
	github.com/outcaste-io/ristretto v0.1.1-0.20220420003845-bd658a460d49 // indirect
	github.com/pelletier/go-toml/v2 v2.3.1 // indirect
	github.com/philhofer/fwd v1.2.0 // indirect
	github.com/pierrec/lz4 v2.5.2+incompatible // indirect
	github.com/pierrec/lz4/v4 v4.1.18 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/power-devops/perfstat v0.0.0-20240221224432-82ca36839d55 // indirect
	github.com/prometheus/client_golang v1.20.5 // indirect
	github.com/prometheus/client_model v0.6.1 // indirect
	github.com/prometheus/common v0.55.0 // indirect
	github.com/prometheus/procfs v0.15.1 // indirect
	github.com/rcrowley/go-metrics v0.0.0-20200313005456-10cdbea86bc0 // indirect
	github.com/rjeczalik/notify v0.9.3 // indirect
	github.com/rogpeppe/go-internal v1.14.1 // indirect
	github.com/rs/xid v1.6.0 // indirect
	github.com/sagikazarmark/locafero v0.11.0 // indirect
	github.com/secure-io/sio-go v0.3.1 // indirect
	github.com/shirou/gopsutil/v4 v4.26.8 // indirect
	github.com/sourcegraph/conc v0.3.1-0.20240121214520-5f936abd7ae8 // indirect
	github.com/spacemonkeygo/errors v0.0.0-20201030155909-2f5f890dbc62 // indirect
	github.com/spaolacci/murmur3 v1.1.0 // indirect
	github.com/spf13/afero v1.15.0 // indirect
	github.com/spf13/cast v1.10.0 // indirect
	github.com/spf13/viper v1.21.0 // indirect
	github.com/streadway/amqp v1.0.0 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	github.com/tidwall/gjson v1.14.2 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.0 // indirect
	github.com/tidwall/sjson v1.2.5 // indirect
	github.com/tinylib/msgp v1.6.4 // indirect
	github.com/tklauser/go-sysconf v0.3.16 // indirect
	github.com/tklauser/numcpus v0.11.0 // indirect
	github.com/valyala/tcplisten v0.0.0-20161114210144-ceec8f93295a // indirect
	github.com/willf/bitset v1.1.11 // indirect
	github.com/willf/bloom v2.0.3+incompatible // indirect
	github.com/xdg/scram v0.0.0-20180814205039-7eeb5667e42c // indirect
	github.com/xdg/stringprep v1.0.0 // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
	github.com/zeebo/admission/v3 v3.0.3 // indirect
	github.com/zeebo/blake3 v0.2.4 // indirect
	github.com/zeebo/errs/v2 v2.0.5 // indirect
	github.com/zeebo/float16 v0.1.0 // indirect
	github.com/zeebo/goof v0.0.0-20230907150950-e9457bc94477 // indirect
	github.com/zeebo/incenc v0.0.0-20180505221441-0d92902eec54 // indirect
	github.com/zeebo/mwc v0.0.7 // indirect
	github.com/zeebo/structs v1.0.3-0.20230601144555-f2db46069602 // indirect
	github.com/zeebo/sudo v1.0.2 // indirect
	github.com/zeebo/xxh3 v1.1.0 // indirect
	go.opencensus.io v0.24.0 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.63.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.61.0 // indirect
	go.opentelemetry.io/otel/metric v1.42.0 // indirect
	go.opentelemetry.io/otel/trace v1.42.0 // indirect
	go.opentelemetry.io/proto/otlp v1.9.0 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap/exp v0.3.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/exp v0.0.0-20240719175910-8a7402abbf56 // indirect
	golang.org/x/mod v0.41.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/telemetry v0.0.0-20260811182544-a038080d80e5 // indirect
	golang.org/x/text v0.42.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	golang.org/x/tools v0.49.0 // indirect
	golang.org/x/xerrors v0.0.0-20240903120638-7835f813f4da // indirect
	google.golang.org/api v0.274.0 // indirect
	google.golang.org/appengine v1.6.8 // indirect
	google.golang.org/genproto v0.0.0-20260319201613-d00831a3d3e7 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260401001100-f93e5f3e9f0f // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260401024825-9d38bb4040a9 // indirect
	google.golang.org/grpc v1.80.0 // indirect
	gopkg.in/ini.v1 v1.67.3 // indirect
	gopkg.in/jcmturner/aescts.v1 v1.0.1 // indirect
	gopkg.in/jcmturner/dnsutils.v1 v1.0.1 // indirect
	gopkg.in/jcmturner/gokrb5.v7 v7.5.0 // indirect
	gopkg.in/jcmturner/rpc.v1 v1.1.0 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	storj.io/infectious v1.0.1 // indirect
	storj.io/monkit-jaeger v0.0.0-20250523220404-454c1b072fad // indirect
	storj.io/picobuf v0.0.4 // indirect
)
