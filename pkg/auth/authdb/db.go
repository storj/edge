// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package authdb

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/spacemonkeygo/monkit/v3"
	"github.com/zeebo/errs"
	"go.uber.org/zap"

	"storj.io/common/encryption"
	"storj.io/common/storj"
	"storj.io/common/version"
	internalAccess "storj.io/edge/internal/access"
	"storj.io/edge/pkg/nodelist"
	"storj.io/edge/pkg/tierquery"
	"storj.io/uplink"
	privateAccess "storj.io/uplink/private/access"
	privateProject "storj.io/uplink/private/project"
)

var (
	mon = monkit.Package()

	// NotFound is returned when a record is not found.
	NotFound = errs.Class("not found")

	// ErrAccessGrant occurs when an invalid access grant is given.
	ErrAccessGrant = errs.Class("access grant")

	// ErrInvalidTag occurs when attempting to use an invalid tag.
	ErrInvalidTag = errs.Class("invalid tag")

	base32Encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

	userAgent = "authservice/" + version.Build.Version.String()
)

// EncKeySizeEncoded is size in base32 bytes + magic byte.
const EncKeySizeEncoded = 28

const encKeyVersionByte = byte(77) // magic number for v1 EncryptionKey encoding
const secKeyVersionByte = byte(78) // magic number for v1 SecretKey encoding

// EncryptionKey is an encryption key that an access/secret are encrypted with.
type EncryptionKey [16]byte

// SecretKey is the secret key used to sign requests.
type SecretKey [32]byte

// ResultRecord is returned when retrieving a record.
type ResultRecord struct {
	AccessGrant string
	SecretKey   SecretKey
	*Record
}

// NewEncryptionKey returns a new random EncryptionKey with initial version byte.
func NewEncryptionKey() (EncryptionKey, error) {
	key := EncryptionKey{encKeyVersionByte}
	if _, err := rand.Read(key[:]); err != nil {
		return key, err
	}
	return key, nil
}

// Hash returns the KeyHash for the EncryptionKey.
func (k EncryptionKey) Hash() KeyHash {
	return KeyHash(sha256.Sum256(k[:]))
}

// FromBase32 loads the EncryptionKey from a lowercase RFC 4648 base32 string.
func (k *EncryptionKey) FromBase32(encoded string) error {
	if len(encoded) != EncKeySizeEncoded {
		return errs.New("alphanumeric encryption key length expected to be %d, was %d", EncKeySizeEncoded, len(encoded))
	}
	data, err := base32Encoding.DecodeString(strings.ToUpper(encoded))
	if err != nil {
		return errs.Wrap(err)
	}
	return k.FromBinary(data)
}

// FromBinary reads the key from binary which must include the version byte.
func (k *EncryptionKey) FromBinary(data []byte) error {
	if data[0] != encKeyVersionByte {
		return errs.New("encryption key did not start with expected byte")
	}
	copy(k[:], data[1:]) // overwrite k
	return nil
}

// ToBase32 returns the EncryptionKey as a lowercase RFC 4648 base32 string.
func (k EncryptionKey) ToBase32() string {
	return toBase32(k.ToBinary())
}

// ToBinary returns the EncryptionKey including the version byte.
func (k EncryptionKey) ToBinary() []byte {
	return append([]byte{encKeyVersionByte}, k[:]...)
}

// ToStorjKey returns the storj.Key equivalent for the EncryptionKey.
func (k EncryptionKey) ToStorjKey() storj.Key {
	var storjKey storj.Key
	copy(storjKey[:], k[:])
	return storjKey
}

// ToBase32 returns the SecretKey as a lowercase RFC 4648 base32 string.
func (s SecretKey) ToBase32() string {
	return toBase32(s.ToBinary())
}

// ToBinary returns the SecretKey including the version byte.
func (s SecretKey) ToBinary() []byte {
	return append([]byte{secKeyVersionByte}, s[:]...)
}

// toBase32 returns the buffer as a lowercase RFC 4648 base32 string.
func toBase32(k []byte) string {
	return strings.ToLower(base32Encoding.EncodeToString(k))
}

// Config contains configuration parameters for a Database.
type Config struct {
	AllowedSatelliteURLs map[storj.NodeURL]struct{}
	RetrieveProjectInfo  bool
	FreeTierAccessLimit  FreeTierAccessLimitConfig
}

// FreeTierAccessLimitConfig contains settings for restricting the access grants of free tier users.
type FreeTierAccessLimitConfig struct {
	MaxDuration time.Duration `help:"maximum amount of time that free tier users' access grants are allowed to be active for. 0 means no limit" default:"0"`
	TierQuery   tierquery.Config
}

// Database wraps Storage implementation and uses it to store encrypted accesses
// and secrets.
type Database struct {
	storage     Storage
	logger      *zap.Logger
	tierService *tierquery.Service

	config       Config
	uplinkConfig uplink.Config

	mu                   sync.Mutex
	allowedSatelliteURLs map[storj.NodeURL]struct{}
}

// NewDatabase constructs a Database. allowedSatelliteAddresses should contain
// the full URL (with a node ID), including port, for each satellite we
// allow for incoming access grants.
func NewDatabase(logger *zap.Logger, storage Storage, config Config) (_ *Database, err error) {
	var tierService *tierquery.Service
	if config.FreeTierAccessLimit.MaxDuration > 0 {
		tierService, err = tierquery.NewService(config.FreeTierAccessLimit.TierQuery, "AuthService")
		if err != nil {
			return nil, errs.Wrap(err)
		}
	}

	return &Database{
		storage:     storage,
		logger:      logger,
		tierService: tierService,
		config:      config,
		uplinkConfig: uplink.Config{
			UserAgent: userAgent,
		},
		allowedSatelliteURLs: config.AllowedSatelliteURLs,
	}, nil
}

// SetAllowedSatellites updates the allowed satellites list from configuration values.
func (db *Database) SetAllowedSatellites(allowedSatelliteURLs map[storj.NodeURL]struct{}) {
	db.mu.Lock()
	db.allowedSatelliteURLs = allowedSatelliteURLs
	db.mu.Unlock()
}

// PutResult represents the result of inserting an access grant into the database.
type PutResult struct {
	SecretKey SecretKey

	// FreeTierRestrictedExpiration is the restricted expiration date of the
	// access grant. It is set if the original expiration date surpassed the
	// free-tier limit.
	FreeTierRestrictedExpiration *time.Time
}

func lowercaseAll(v []string) (rv []string) {
	rv = make([]string, 0, len(v))
	for _, v := range v {
		rv = append(rv, strings.ToLower(v))
	}
	return rv
}

func processUsageTags(tags []string) ([]string, error) {
	tags = lowercaseAll(tags)
	slices.Sort(tags)
	tags = slices.Compact(tags)
	filtered := make([]string, 0, len(tags))
	for _, tag := range tags {
		if strings.Contains(tag, ",") {
			return nil, ErrInvalidTag.New("can't contain commas")
		}
		switch tag {
		case "mcp":
			filtered = append(filtered, tag)
		case "":
		default:
			return nil, ErrInvalidTag.New("unknown tag %q", tag)
		}
	}
	return filtered, nil
}

// Put encrypts the access grant with the key and stores it under the hash of
// the encryption key. It rejects access grants with expiration times that are
// before a minute from now.
//
// If the access grant's owner is a free-tier user, expiration date restrictions
// may be imposed on the access grant according to the FreeTierAccessLimitConfig
// used when constructing the database.
func (db *Database) Put(ctx context.Context, key EncryptionKey, accessGrant string, public bool, usageTags []string) (result PutResult, err error) {
	defer mon.Task()(&ctx)(&err)

	usageTags, err = processUsageTags(usageTags)
	if err != nil {
		return PutResult{}, err
	}

	access, err := uplink.ParseAccess(accessGrant)
	if err != nil {
		return PutResult{}, ErrAccessGrant.Wrap(err)
	}

	// Check that the satellite address embedded in the access grant is on the
	// allowed list.
	satelliteAddr := access.SatelliteAddress()
	nodeURL, err := nodelist.ParseNodeURL(satelliteAddr)
	if err != nil {
		return PutResult{}, ErrAccessGrant.Wrap(err)
	}

	db.mu.Lock()
	_, ok := db.allowedSatelliteURLs[nodeURL]
	db.mu.Unlock()
	if !ok {
		return PutResult{}, ErrAccessGrant.New("disallowed satellite: %q", satelliteAddr)
	}

	apiKey := privateAccess.APIKey(access)

	expiration, err := internalAccess.APIKeyExpiration(apiKey)
	if err != nil {
		return PutResult{}, ErrAccessGrant.Wrap(err)
	}
	if expiration != nil && expiration.Before(time.Now().Add(time.Minute)) {
		return PutResult{}, ErrAccessGrant.New("expiration cannot be shorter than a minute")
	}

	if public && db.config.FreeTierAccessLimit.MaxDuration > 0 {
		paidTier, err := db.tierService.Do(ctx, access, "")
		if err != nil {
			return PutResult{}, errs.Wrap(err)
		}

		maxExpiration := time.Now().Add(db.config.FreeTierAccessLimit.MaxDuration)
		if !paidTier && (expiration == nil || expiration.After(maxExpiration)) {
			restricted, err := privateAccess.Share(access, privateAccess.WithAllPermissions(), privateAccess.NotAfter(maxExpiration))
			if err != nil {
				return PutResult{}, errs.Wrap(err)
			}

			accessGrant, err = restricted.Serialize()
			if err != nil {
				return PutResult{}, errs.Wrap(err)
			}

			access = restricted
			apiKey = privateAccess.APIKey(access)
			expiration = &maxExpiration
			result.FreeTierRestrictedExpiration = &maxExpiration
		}
	}

	if _, err := rand.Read(result.SecretKey[:]); err != nil {
		return PutResult{}, errs.Wrap(err)
	}

	storjKey := key.ToStorjKey()
	// note that we currently always use the same nonce here - all zero's for secret keys
	encryptedSecretKey, err := encryption.Encrypt(result.SecretKey[:], storj.EncAESGCM, &storjKey, &storj.Nonce{})
	if err != nil {
		return PutResult{}, errs.Wrap(err)
	}
	// note that we currently always use the same nonce here - one then all zero's for access grants
	encryptedAccessGrant, err := encryption.Encrypt([]byte(accessGrant), storj.EncAESGCM, &storjKey, &storj.Nonce{1})
	if err != nil {
		return PutResult{}, errs.Wrap(err)
	}

	var projInfo privateProject.Info
	if db.config.RetrieveProjectInfo {
		timeoutCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		projInfo, err = privateProject.GetProjectInfo(timeoutCtx, db.uplinkConfig, access)
		if err != nil {
			db.logger.Warn("retrieve project info failed", zap.Error(err))
			projInfo = privateProject.Info{} // just in case, zero it
			mon.Event("retrieve_project_info_failed")
		}
	}

	record := &Record{
		SatelliteAddress:     satelliteAddr,
		PublicProjectID:      projInfo.PublicId.Bytes(),
		MacaroonHead:         apiKey.Head(),
		EncryptedSecretKey:   encryptedSecretKey,
		EncryptedAccessGrant: encryptedAccessGrant,
		Public:               public,
		ExpiresAt:            expiration,
		UsageTags:            usageTags,
		ProjectCreatedAt:     projInfo.CreatedAt,
	}

	if err = db.storage.Put(ctx, key.Hash(), record); err != nil {
		return PutResult{}, errs.Wrap(err)
	}

	return result, nil
}

// Get retrieves an access grant and secret key, looked up by the hash of the
// access key, and then decrypted.
func (db *Database) Get(ctx context.Context, accessKeyID EncryptionKey) (result ResultRecord, err error) {
	defer mon.Task()(&ctx)(&err)

	dbRecord, err := db.storage.Get(ctx, accessKeyID.Hash())
	if err != nil {
		return result, errs.Wrap(err)
	} else if dbRecord == nil {
		return result, NotFound.New("key hash: %x", accessKeyID.Hash())
	}

	storjKey := accessKeyID.ToStorjKey()
	// note that we currently always use the same nonce here - all zero's for secret keys
	sk, err := encryption.Decrypt(dbRecord.EncryptedSecretKey, storj.EncAESGCM, &storjKey, &storj.Nonce{})
	if err != nil {
		return result, errs.Wrap(err)
	}

	var secretKey SecretKey

	copy(secretKey[:], sk)
	// note that we currently always use the same nonce here - one then all zero's for access grants
	ag, err := encryption.Decrypt(dbRecord.EncryptedAccessGrant, storj.EncAESGCM, &storjKey, &storj.Nonce{1})
	if err != nil {
		return result, errs.Wrap(err)
	}

	return ResultRecord{
		AccessGrant: string(ag),
		SecretKey:   secretKey,
		Record:      dbRecord,
	}, nil
}

// HealthCheck ensures the underlying storage backend works and returns an error
// otherwise.
func (db *Database) HealthCheck(ctx context.Context) (err error) {
	defer mon.Task()(&ctx)(&err)

	return errs.Wrap(db.storage.HealthCheck(ctx))
}
