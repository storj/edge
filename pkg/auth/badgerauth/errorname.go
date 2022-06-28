// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package badgerauth

import (
	badger "github.com/outcaste-io/badger/v3"
	"github.com/spacemonkeygo/monkit/v3"
	"github.com/zeebo/errs"

	"storj.io/gateway-mt/pkg/auth/authdb"
)

func init() {
	monkit.AddErrorNameHandler(errorName)
}

// errorName fits the requirements for monkit.AddErrorNameHandler so that we can
// provide a useful error tag with mon.Task().
func errorName(err error) (name string, ok bool) {
	switch {
	case authdb.KeyHashError.Has(err):
		name = "KeyHash"
	case authdb.Invalid.Has(err):
		name = "InvalidRecord"
	case BackupError.Has(err):
		name = "Backup"
	case ProtoError.Has(err):
		name = "Proto"
	case ReplicationLogError.Has(err):
		// We have a wrapped error, but we want to gain more insight into
		// whether the error contains some other error we know about.
		//
		// We check ReplicationLogError first because it can contain ClockError
		// and not the other way around. TODO(artur, sean): how to make sure we
		// don't make a mistake regarding this relation in the future?
		name = "ReplicationLog"
		if unwrapped, ok := errorName(errs.Unwrap(err)); ok {
			name += ":" + unwrapped
		}
	case ClockError.Has(err):
		name = "Clock"
		if unwrapped, ok := errorName(errs.Unwrap(err)); ok {
			name += ":" + unwrapped
		}
	case NodeIDError.Has(err):
		name = "NodeID"
		if unwrapped, ok := errorName(errs.Unwrap(err)); ok {
			name += ":" + unwrapped
		}
	case errs.Is(err, ErrKeyAlreadyExists):
		name = "KeyAlreadyExists"
	case errs.Is(err, errOperationNotSupported):
		name = "OperationNotSupported"
	case errs.Is(err, errKeyAlreadyExistsRecordsNotEqual):
		name = "KeyAlreadyExistsRecordsNotEqual"
	case errs.Is(err, badger.ErrKeyNotFound):
		name = "KeyNotFound"
	case errs.Is(err, badger.ErrValueLogSize):
		name = "ValueLogSize"
	case errs.Is(err, badger.ErrTxnTooBig):
		name = "TxnTooBig"
	case errs.Is(err, badger.ErrConflict):
		name = "Conflict"
	case errs.Is(err, badger.ErrReadOnlyTxn):
		name = "ReadonlyTxn"
	case errs.Is(err, badger.ErrDiscardedTxn):
		name = "DiscardedTxn"
	case errs.Is(err, badger.ErrEmptyKey):
		name = "EmptyKey"
	case errs.Is(err, badger.ErrInvalidKey):
		name = "InvalidKey"
	case errs.Is(err, badger.ErrBannedKey):
		name = "BannedKey"
	case errs.Is(err, badger.ErrThresholdZero):
		name = "ThresholdZero"
	case errs.Is(err, badger.ErrNoRewrite):
		name = "NoRewrite"
	case errs.Is(err, badger.ErrRejected):
		name = "Rejected"
	case errs.Is(err, badger.ErrInvalidRequest):
		name = "InvalidRequest"
	case errs.Is(err, badger.ErrManagedTxn):
		name = "ManagedTxn"
	case errs.Is(err, badger.ErrNamespaceMode):
		name = "NamespaceMode"
	case errs.Is(err, badger.ErrInvalidDump):
		name = "InvalidDump"
	case errs.Is(err, badger.ErrZeroBandwidth):
		name = "ZeroBandwidth"
	case errs.Is(err, badger.ErrWindowsNotSupported):
		name = "WindowsNotSupported"
	case errs.Is(err, badger.ErrPlan9NotSupported):
		name = "Plan9NotSupported"
	case errs.Is(err, badger.ErrTruncateNeeded):
		name = "TruncateNeeded"
	case errs.Is(err, badger.ErrBlockedWrites):
		name = "BlockedWrites"
	case errs.Is(err, badger.ErrNilCallback):
		name = "NilCallback"
	case errs.Is(err, badger.ErrEncryptionKeyMismatch):
		name = "EncryptionKeyMismatch"
	case errs.Is(err, badger.ErrInvalidDataKeyID):
		name = "InvalidDataKeyID"
	case errs.Is(err, badger.ErrInvalidEncryptionKey):
		name = "InvalidEncryptionKey"
	case errs.Is(err, badger.ErrGCInMemoryMode):
		name = "GCInMemoryMode"
	case errs.Is(err, badger.ErrDBClosed):
		name = "DBClosed"
	}

	return name, len(name) > 0
}
