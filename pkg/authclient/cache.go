// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package authclient

import (
	"github.com/zeebo/errs"

	"storj.io/common/encryption"
	"storj.io/common/storj"
)

var (
	cacheEncryptError = errs.Class("auth response cache encrypt")
	cacheDecryptError = errs.Class("auth response cache decrypt")
)

type cachedAuthServiceResponse struct {
	accessGrant []byte
	secretKey   []byte
	public      bool
	err         error
}

func encryptResponse(accessKeyID string, resp AuthServiceResponse, respErr error) (cachedAuthServiceResponse, error) {
	key, err := storj.NewKey([]byte(accessKeyID))
	if err != nil {
		return cachedAuthServiceResponse{}, cacheEncryptError.Wrap(err)
	}

	// note: we always use the same nonce here - all zero's for secret keys, one then all zero's for access grants
	secretKey, err := encryption.Encrypt([]byte(resp.SecretKey), storj.EncAESGCM, key, &storj.Nonce{})
	if err != nil {
		return cachedAuthServiceResponse{}, cacheEncryptError.Wrap(err)
	}
	accessGrant, err := encryption.Encrypt([]byte(resp.AccessGrant), storj.EncAESGCM, key, &storj.Nonce{1})
	if err != nil {
		return cachedAuthServiceResponse{}, cacheEncryptError.Wrap(err)
	}

	return cachedAuthServiceResponse{
		accessGrant: accessGrant,
		secretKey:   secretKey,
		public:      resp.Public,
		err:         respErr,
	}, nil
}

func (resp *cachedAuthServiceResponse) decrypt(accessKeyID string) (AuthServiceResponse, error) {
	key, err := storj.NewKey([]byte(accessKeyID))
	if err != nil {
		return AuthServiceResponse{}, cacheDecryptError.Wrap(err)
	}

	// note: we always use the same nonce here - all zero's for secret keys, one then all zero's for access grants
	secretKey, err := encryption.Decrypt(resp.secretKey, storj.EncAESGCM, key, &storj.Nonce{})
	if err != nil {
		return AuthServiceResponse{}, cacheDecryptError.Wrap(err)
	}
	accessGrant, err := encryption.Decrypt(resp.accessGrant, storj.EncAESGCM, key, &storj.Nonce{1})
	if err != nil {
		return AuthServiceResponse{}, cacheDecryptError.Wrap(err)
	}

	return AuthServiceResponse{
		AccessGrant: string(accessGrant),
		SecretKey:   string(secretKey),
		Public:      resp.public,
	}, nil
}
