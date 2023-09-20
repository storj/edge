// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package badgerauth

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/outcaste-io/badger/v3"
	"github.com/spacemonkeygo/monkit/v3"
	"github.com/zeebo/errs"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/sync/errgroup"

	"storj.io/common/errs2"
	"storj.io/common/memory"
	"storj.io/common/rpc"
	"storj.io/common/rpc/rpcpool"
	"storj.io/common/rpc/rpcstatus"
	"storj.io/common/sync2"
	"storj.io/drpc/drpcconn"
	"storj.io/drpc/drpcmux"
	"storj.io/drpc/drpcserver"
	"storj.io/gateway-mt/pkg/auth/authdb"
	"storj.io/gateway-mt/pkg/auth/badgerauth/pb"
	"storj.io/gateway-mt/pkg/backoff"
)

var (
	mon = monkit.Package()

	// Error is the default error class for the badgerauth package.
	Error = errs.Class("badgerauth")

	// DialError is an error class for dial failures.
	DialError = errs.Class("dial")
)

// Config provides options for creating a Node.
//
// Keep this in sync with badgerauthtest.setConfigDefaults.
type Config struct {
	// NOTE(artur): I have received feedback that we are headed towards many
	// options that no one understands how to use correctly. It might be
	// necessary to make the config thinner and autoscale or explain necessary
	// and fine-tune defaults. CockroachDB is a good (or bad?) example of how to
	// have not too many options; the only thing that the user can configure
	// while setting up a node is the join list.

	ID NodeID `user:"true" help:"unique identifier for the node" default:""`

	FirstStart bool `user:"true" help:"allow start with empty storage" devDefault:"true" releaseDefault:"false"`
	// Path is where to store data. Empty means in memory.
	Path string `user:"true" help:"path where to store data" default:""`

	Address string   `user:"true" help:"address that the node listens on" default:":20004"`
	Join    []string `user:"true" help:"comma delimited list of cluster peers" default:""`
	// CertsDir is a path to a directory for certificates for mutual
	// authentication. If empty, no certificates will be loaded, and it will be
	// impossible to connect the node to any cluster.
	CertsDir string `user:"true" help:"directory for certificates for mutual authentication"`

	// ReplicationInterval defines how often to connect and request status from
	// other nodes.
	ReplicationInterval time.Duration `user:"true" help:"how often to replicate" default:"30s" devDefault:"5s"`
	// ReplicationLimit is per node ID limit of replication response entries to
	// return.
	ReplicationLimit int `user:"true" help:"maximum entries returned in replication response" default:"1000"`
	// ConflictBackoff configures retries for conflicting transactions that may
	// occur when Node's underlying storage engine is under heavy load.
	ConflictBackoff backoff.ExponentialBackoff

	// InsecureDisableTLS allows disabling tls for testing.
	InsecureDisableTLS bool `internal:"true"`

	Backup BackupConfig
}

// Node is distributed auth storage node that wraps DB with machinery to
// replicate records from and to other nodes.
type Node struct {
	log *zap.Logger
	db  *DB

	config Config

	Backup       *Backup
	tls          *tls.Config
	pooledDialer rpc.Dialer
	listener     net.Listener
	mux          *drpcmux.Mux
	server       *drpcserver.Server
	admin        *Admin
	peers        []*Peer

	gc        sync2.Cycle
	SyncCycle sync2.Cycle
}

// Below is a compile-time check ensuring Node implements the
// DRPCReplicationServiceServer interface.
var _ pb.DRPCReplicationServiceServer = (*Node)(nil)

// New constructs new Node.
func New(log *zap.Logger, config Config) (_ *Node, err error) {
	if log == nil {
		return nil, Error.New("needs non-nil logger")
	}

	node := &Node{
		log:    log,
		config: config,
		mux:    drpcmux.New(),
	}

	defer func() {
		if err != nil {
			_ = node.Close()
		}
	}()

	node.db, err = OpenDB(log, config)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	if config.Backup.Enabled {
		s3Client, err := minio.New(config.Backup.Endpoint, &minio.Options{
			Creds:  credentials.NewStaticV4(config.Backup.AccessKeyID, config.Backup.SecretAccessKey, ""),
			Secure: !config.InsecureDisableTLS,
		})
		if err != nil {
			return nil, Error.New("failed to create s3 client: %w", err)
		}
		node.Backup = NewBackup(log, node.db, s3Client)
	}

	if !config.InsecureDisableTLS {
		opts := TLSOptions{
			CertsDir: config.CertsDir,
		}
		node.tls, err = opts.Load()
		if err != nil {
			return nil, Error.New("failed to load tls config: %w", err)
		}
	}

	c := rpc.NewHybridConnector()
	c.SetSendDRPCMuxHeader(false)

	manager := rpc.NewDefaultManagerOptions()
	// TODO(artur): ideally, this is calculated using a formula like this one:
	//  peers * replicationLimit * accessGrantLimit + padding
	// Example:
	//  peers=5, replicationLimit=1000, accessGrantLimit=4KiB, padding=4MiB ~ 27.44 MiB
	manager.Reader.MaximumBufferSize = 40 * memory.MiB.Int()
	node.pooledDialer = rpc.Dialer{
		HostnameTLSConfig: node.tls,
		DialTimeout:       10 * time.Second,
		Pool:              rpc.NewDefaultConnectionPool(),
		ConnectionOptions: drpcconn.Options{
			Manager: manager,
		},
		Connector: c,
	}

	if err = pb.DRPCRegisterReplicationService(node.mux, node); err != nil {
		return nil, Error.New("failed to register server: %w", err)
	}

	node.admin = NewAdmin(node.db)
	if err = pb.DRPCRegisterAdminService(node.mux, node.admin); err != nil {
		return nil, Error.New("failed to register server: %w", err)
	}

	serverOptions := drpcserver.Options{
		Manager: rpc.NewDefaultManagerOptions(),
		Log:     func(err error) { log.Named("network").Debug(err.Error()) },
	}
	node.server = drpcserver.NewWithOptions(node.mux, serverOptions)

	tcpListener, err := net.Listen("tcp", config.Address)
	if err != nil {
		return nil, Error.New("failed to listen on %q: %w", config.Address, err)
	}

	if !config.InsecureDisableTLS {
		node.listener = tls.NewListener(tcpListener, node.tls)
	} else {
		node.listener = tcpListener
	}

	node.gc.SetInterval(5 * time.Minute)
	node.SyncCycle.SetInterval(config.ReplicationInterval)

	return node, nil
}

// ID returns the configured node id.
func (node *Node) ID() NodeID { return node.config.ID }

// Address returns the server address.
func (node *Node) Address() string {
	return node.listener.Addr().String()
}

// Put proxies DB's Put.
func (node *Node) Put(ctx context.Context, keyHash authdb.KeyHash, record *authdb.Record) error {
	return node.db.Put(ctx, keyHash, record)
}

// PutAtTime proxies DB's PutAtTime.
func (node *Node) PutAtTime(ctx context.Context, keyHash authdb.KeyHash, record *authdb.Record, now time.Time) error {
	return node.db.PutAtTime(ctx, keyHash, record, now)
}

// Get returns a record from the database. If the record isn't found, we consult
// peer nodes to see if they have the record. This covers the case of a user
// putting a record onto one authservice node, but then retrieving it from
// another before the record has been fully synced.
func (node *Node) Get(ctx context.Context, keyHash authdb.KeyHash) (record *authdb.Record, err error) {
	defer mon.Task(node.db.eventTags()...)(&ctx)(&err)

	record, err = node.db.Get(ctx, keyHash)
	if err != nil {
		return nil, err
	}

	// Fast path (the record is available locally):
	if record != nil {
		return record, nil
	}

	// Slow path (we need to contact other nodes):
	if len(node.peers) == 0 {
		// We have no peers, so we end here.
		return nil, nil
	}

	// The idea behind this is that the first result cancels the rest, and if
	// multiple succeed at once, subsequent results will be discarded by default
	// case. When the group is finished, we do a non-blocking read which is
	// guaranteed to succeed if the channel has value inside. If we got to the
	// end without finding any record, such as the case of not being able to
	// contact other nodes, then we don't return an error so authclient doesn't
	// block requests indefinitely through backoff/retry.

	result := make(chan *authdb.Record, 1)

	var group errs2.Group

	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()

	for _, peer := range node.peers {
		peer := peer
		group.Go(func() error {
			r, err := peer.Peek(ctx, keyHash)
			if err != nil {
				return errs.New("%s: %w", peer.address, err)
			}

			select {
			case result <- &authdb.Record{
				SatelliteAddress:     r.SatelliteAddress,
				MacaroonHead:         r.MacaroonHead,
				EncryptedSecretKey:   r.EncryptedSecretKey,
				EncryptedAccessGrant: r.EncryptedAccessGrant,
				ExpiresAt:            timestampToTime(r.ExpiresAtUnix),
				Public:               r.Public,
			}:
				cancel()
			default:
			}

			return nil
		})
	}

	allErrs := group.Wait()

	select {
	case record = <-result:
		// If we had at least one success, we drop all errors and just go ahead
		// and return the first result.
		return record, nil
	default:
	}

	var errGroup errs.Group
	for _, e := range allErrs {
		if !(errs2.IsRPC(e, rpcstatus.NotFound) || errs2.IsCanceled(e)) {
			errGroup.Add(e)
		}
	}

	if errGroup.Err() != nil {
		node.log.Warn("broadcasted Get unexpected error", zap.Error(errGroup.Err()))
	}

	return nil, nil
}

// PingDB proxies DB's PingDB.
func (node *Node) PingDB(ctx context.Context) error {
	return node.db.PingDB(ctx)
}

// Run runs the server and the associated servers.
func (node *Node) Run(ctx context.Context) error {
	if len(node.config.Join) == 0 || len(node.config.CertsDir) == 0 {
		node.log.Warn("node is alone in the cluster (empty join and/or certs-dir parameters)")
	}

	group, gCtx := errgroup.WithContext(ctx)

	node.gc.Start(gCtx, group, node.db.gcValueLog)
	defer node.gc.Close()

	if node.Backup != nil {
		node.Backup.SyncCycle.Start(gCtx, group, node.Backup.RunOnce)
		defer node.Backup.SyncCycle.Close()
	}

	for _, join := range node.config.Join {
		node.peers = append(node.peers, NewPeer(node, join))
	}
	node.SyncCycle.Start(gCtx, group, node.syncAll)
	defer node.SyncCycle.Close()

	group.Go(func() error {
		node.log.Info("Starting replication server", zap.String("address", node.listener.Addr().String()))
		return Error.Wrap(node.server.Serve(gCtx, node.listener))
	})

	return Error.Wrap(group.Wait())
}

// syncAll tries to synchronize all nodes.
func (node *Node) syncAll(ctx context.Context) error {
	for _, peer := range node.peers {
		if err := IgnoreDialFailures(peer.Sync(ctx)); err != nil {
			return Error.Wrap(err)
		}
	}
	return nil
}

// Close releases underlying resources.
func (node *Node) Close() error {
	var g errs.Group

	// 1. incoming replication's server
	if node.listener != nil {
		// if the server is started, then `server.Serve` automatically closes
		// the listener.
		_ = node.listener.Close()
	}
	// 2. outgoing replication is closed after Run finishes
	// 3. dialer
	g.Add(node.pooledDialer.Pool.Close())
	// 4. backups are closed after Run finishes
	// 5. storage engine's GC is closed after Run finishes
	// 6. storage engine
	if node.db != nil {
		g.Add(node.db.Close())
	}

	return Error.Wrap(g.Err())
}

// Ping allows to fetch information about the node.
func (node *Node) Ping(ctx context.Context, req *pb.PingRequest) (*pb.PingResponse, error) {
	return &pb.PingResponse{
		NodeId: node.config.ID.Bytes(),
	}, nil
}

// Peek allows fetching a specific record from the node.
func (node *Node) Peek(ctx context.Context, req *pb.PeekRequest) (_ *pb.PeekResponse, err error) {
	defer mon.Task()(&ctx)(&err)

	var kh authdb.KeyHash
	if err = kh.SetBytes(req.EncryptionKeyHash); err != nil {
		return nil, errToRPCStatusErr(err)
	}

	record, err := node.db.lookupRecord(kh)
	if err != nil {
		return nil, errToRPCStatusErr(err)
	}

	return &pb.PeekResponse{
		Record: record,
	}, nil
}

// Replicate implements a node's ability to ship its replication log/records to
// another node. It responds with RPC errors only.
func (node *Node) Replicate(ctx context.Context, req *pb.ReplicationRequest) (_ *pb.ReplicationResponse, err error) {
	defer mon.Task()(&ctx)(&err)

	node.log.Info("incoming replication request", zap.Object("clocks", fromRequestEntries(req.Entries)))

	var response pb.ReplicationResponse

	for _, reqEntry := range req.Entries {
		select {
		case <-ctx.Done():
			err := ctx.Err()
			node.log.Error("replication response canceled", zap.Error(err))
			return nil, rpcstatus.Error(rpcstatus.Canceled, err.Error())
		default:
			// continue
		}

		var id NodeID

		if err := id.SetBytes(reqEntry.NodeId); err != nil {
			node.log.Error("replication response failed", zap.Error(err))
			return nil, rpcstatus.Error(rpcstatus.InvalidArgument, err.Error())
		}

		entries, err := node.db.findResponseEntries(id, Clock(reqEntry.Clock))
		if err != nil {
			node.log.Error("replication response failed", zap.Error(err))
			return nil, rpcstatus.Error(rpcstatus.Internal, err.Error())
		}

		response.Entries = append(response.Entries, entries...)
	}

	node.log.Info("incoming replication response", zap.Object("delta", fromResponseEntries(response.Entries)))

	return &response, nil
}

// UnderlyingDB returns underlying DB. This method is most useful in tests.
func (node *Node) UnderlyingDB() *DB {
	return node.db
}

// TestingSetJoin sets peer nodes to join to.
func (node *Node) TestingSetJoin(addresses []string) {
	node.config.Join = addresses
}

// TestingPeers allows to access the peers for testing.
func (node *Node) TestingPeers(ctx context.Context) []*Peer {
	return node.peers
}

// Peer represents a node peer replication logic.
type Peer struct {
	address string
	node    *Node
	log     *zap.Logger

	ensuredClock bool
	mu           sync.Mutex
	status       PeerStatus
}

// PeerStatus contains last known peer status.
type PeerStatus struct {
	Address string
	NodeID  NodeID

	LastUpdated time.Time
	LastWasUp   bool
	LastError   error

	Clock Clock
}

// NewPeer returns a replication peer.
func NewPeer(node *Node, address string) *Peer {
	peer := &Peer{
		address: address,
		node:    node,
		log:     node.log.Named(address),
	}
	peer.status.Address = address
	return peer
}

// Sync runs the synchronization step once.
func (peer *Peer) Sync(ctx context.Context) (err error) {
	defer mon.Task()(&ctx)(&err)

	// Set timeout for the whole sync operation. See storj/storj-private#284.
	// Note: timeout for dial will be min(this timeout, rpc.Dialer.DialTimeout).
	ctx, cancel := context.WithTimeout(ctx, peer.node.config.ReplicationInterval)
	defer cancel()

	return peer.withClient(ctx,
		func(ctx context.Context, client pb.DRPCReplicationServiceClient) (err error) {
			defer mon.Task()(&ctx)(&err)

			ok, err := peer.pingClient(ctx, client)
			if err != nil {
				return err // already wrapped if needed
			}
			if !ok {
				peer.log.Warn("peer is down or misbehaving, skipping records sync")
				return nil
			}

			if err = peer.syncRecords(ctx, client); err != nil {
				return err // already wrapped if needed
			}

			return nil
		}, "sync")
}

// Peek returns a record from the peer.
func (peer *Peer) Peek(ctx context.Context, keyHash authdb.KeyHash) (record *pb.Record, err error) {
	defer mon.Task()(&ctx)(&err)

	return record, peer.withClient(ctx,
		func(ctx context.Context, client pb.DRPCReplicationServiceClient) (err error) {
			defer mon.Task()(&ctx)(&err)

			resp, err := client.Peek(ctx, &pb.PeekRequest{EncryptionKeyHash: keyHash.Bytes()})
			if err != nil {
				return Error.Wrap(err)
			}
			record = resp.Record

			return nil
		}, "peek")
}

func (peer *Peer) pingClient(ctx context.Context, client pb.DRPCReplicationServiceClient) (ok bool, err error) {
	defer mon.Task()(&ctx)(&err)

	resp, err := client.Ping(ctx, &pb.PingRequest{})
	if err != nil {
		peer.statusDown(err)
		return false, nil
	}

	var clientID NodeID
	if err = clientID.SetBytes(resp.NodeId); err != nil {
		peer.statusDown(err)
		return false, nil
	}
	peer.statusUp()

	if clientID == peer.node.ID() {
		return false, Error.New("started with the same node ID (%s) as %s:", clientID, peer.address)
	}

	if !peer.ensuredClock {
		if err = peer.node.db.ensureClock(ctx, clientID); err != nil {
			return false, Error.New("couldn't ensure clock for %s: %w", clientID, err)
		}
		peer.ensuredClock = true
	}

	return true, nil
}

func (peer *Peer) syncRecords(ctx context.Context, client pb.DRPCReplicationServiceClient) (err error) {
	defer mon.Task()(&ctx)(&err)

	db := peer.node.db

	requestEntries, err := db.buildRequestEntries()
	if err != nil {
		peer.log.Error("failed to accumulate node IDs/clocks", zap.Error(err))
		return nil
	}

	peer.log.Info("outgoing replication: requesting records from this peer", zap.Object("clocks", fromRequestEntries(requestEntries)))

	// No need to make this call in a transaction since this replication process
	// doesn't run concurrently as of now.
	response, err := client.Replicate(ctx, &pb.ReplicationRequest{
		Entries: requestEntries,
	})
	if err != nil {
		peer.log.Error("failed to request replication", zap.Error(err))
		return nil
	}

	if err = db.insertResponseEntries(ctx, response); err != nil {
		peer.log.Error("failed to process replication response", zap.Error(err))
		return nil
	}

	peer.log.Info("outgoing replication: inserted new records from this peer", zap.Object("delta", fromResponseEntries(response.Entries)))

	return nil
}

func (peer *Peer) withClient(ctx context.Context, fn func(ctx context.Context, client pb.DRPCReplicationServiceClient) error, task string) (err error) {
	defer mon.Task()(&ctx)(&err)

	dialFinished := mon.TaskNamed("dial", monkit.NewSeriesTag("address", peer.address))(&ctx)

	var conn *rpc.Conn
	if !peer.node.config.InsecureDisableTLS {
		conn, err = peer.node.pooledDialer.DialAddressHostnameVerification(rpcpool.WithForceDial(ctx), peer.address)
	} else {
		conn, err = peer.node.pooledDialer.DialAddressUnencrypted(rpcpool.WithForceDial(ctx), peer.address)
	}
	dialFinished(&err)

	if err != nil {
		peer.log.Named(task).Warn("dial failed", zap.String("address", peer.address), zap.Error(err))
		peer.statusDown(err)
		return DialError.Wrap(err)
	}

	// NOTE(artur): Calling Close on pooled connection doesn't close it. It only
	// closes the handle to the underlying resource.
	defer func() { _ = conn.Close() }()

	return fn(ctx, pb.NewDRPCReplicationServiceClient(conn))
}

// statusUp changes peer status to up.
func (peer *Peer) statusUp() {
	mon.Event("as_badgerauth_peer_up", monkit.NewSeriesTag("address", peer.address))
	peer.changeStatus(func(status *PeerStatus) {
		status.LastUpdated = time.Now()
		status.LastWasUp = true
		status.LastError = nil
	})
}

// statusDown changes peer status to down.
func (peer *Peer) statusDown(err error) {
	mon.Event("as_badgerauth_peer_down", monkit.NewSeriesTag("address", peer.address))
	peer.changeStatus(func(status *PeerStatus) {
		status.LastUpdated = time.Now()
		status.LastWasUp = false
		status.LastError = err
	})
}

// changeStatus uses a callback to safely change peer status.
func (peer *Peer) changeStatus(fn func(status *PeerStatus)) {
	peer.mu.Lock()
	defer peer.mu.Unlock()
	fn(&peer.status)
}

// Status returns a snapshot of the peer status.
func (peer *Peer) Status() PeerStatus {
	peer.mu.Lock()
	defer peer.mu.Unlock()
	return peer.status
}

// IgnoreDialFailures returns nil if err contains DialError (and err otherwise).
func IgnoreDialFailures(err error) error {
	if DialError.Has(err) {
		return nil
	}
	return err
}

type clocksLogObject map[string]uint64

func (o clocksLogObject) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	var ids []string
	for id := range o {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		enc.AddUint64(id, o[id])
	}
	return nil
}

func fromRequestEntries(entries []*pb.ReplicationRequestEntry) clocksLogObject {
	clocks := make(clocksLogObject)
	for _, e := range entries {
		var id NodeID
		if err := id.SetBytes(e.NodeId); err != nil {
			clocks[hex.EncodeToString(e.NodeId)] = e.Clock
		} else {
			clocks[id.String()] = e.Clock
		}
	}
	return clocks
}

func fromResponseEntries(entries []*pb.ReplicationResponseEntry) clocksLogObject {
	clocks := make(clocksLogObject)
	for _, e := range entries {
		var id NodeID
		if err := id.SetBytes(e.NodeId); err != nil {
			clocks[hex.EncodeToString(e.NodeId)]++
		} else {
			clocks[id.String()]++
		}
	}
	return clocks
}

func errToRPCStatusErr(err error) error {
	switch {
	case err == nil:
		return nil
	case ProtoError.Has(err),
		authdb.KeyHashError.Has(err),
		errs.Is(err, badger.ErrInvalidKey),
		errs.Is(err, badger.ErrBannedKey),
		errs.Is(err, badger.ErrEmptyKey):
		return rpcstatus.Error(rpcstatus.InvalidArgument, err.Error())
	case errs.Is(err, badger.ErrKeyNotFound):
		return rpcstatus.Error(rpcstatus.NotFound, err.Error())
	default:
		return rpcstatus.Error(rpcstatus.Internal, err.Error())
	}
}
