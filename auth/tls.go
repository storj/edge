// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package auth

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"path/filepath"

	"github.com/zeebo/errs"
	"golang.org/x/crypto/acme/autocert"
)

// TLSInfo is a struct to handle the preferred/configured TLS options.
type TLSInfo struct {
	LetsEncrypt bool
	CertFile    string
	KeyFile     string
	PublicURL   string
	ConfigDir   string
}

func configureTLS(config *TLSInfo, handler http.Handler) (*tls.Config, http.Handler, error) {
	if config.LetsEncrypt {
		return configureLetsEncrypt(config, handler)
	}

	switch {
	case config.CertFile != "" && config.KeyFile != "":
	case config.CertFile == "" && config.KeyFile == "":
		return nil, handler, nil
	case config.CertFile != "" && config.KeyFile == "":
		return nil, nil, errs.New("key file must be provided with cert file")
	case config.CertFile == "" && config.KeyFile != "":
		return nil, nil, errs.New("cert file must be provided with key file")
	}

	cert, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
	if err != nil {
		return nil, nil, errs.New("unable to load server keypair: %v", err)
	}

	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	}, handler, nil
}

func configureLetsEncrypt(config *TLSInfo, handler http.Handler) (*tls.Config, http.Handler, error) {
	parsedURL, err := url.Parse(config.PublicURL)
	if err != nil {
		return nil, nil, err
	}
	certManager := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(parsedURL.Host),
		Cache:      autocert.DirCache(filepath.Join(config.ConfigDir, ".certs")),
	}

	tlsConfig := &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: certManager.GetCertificate,
	}

	return tlsConfig, certManager.HTTPHandler(handler), nil
}
