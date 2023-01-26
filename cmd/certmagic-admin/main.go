// Copyright (C) 2023 Storj Labs, Inc.
// See LICENSE for copying information.

package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/fatih/color"
	"github.com/grantae/certinfo"
	"github.com/libdns/googleclouddns"
	"github.com/zeebo/clingy"
	"go.uber.org/zap"

	"storj.io/gateway-mt/pkg/certstorage"
	"storj.io/gateway-mt/pkg/gpublicca"
)

type certmagicConfig struct {
	// KeyFile is a path to a file containing the CertMagic service account key.
	KeyFile string

	// GCloudDNSProject is the project where the Google Cloud DNS zone exists.
	GCloudDNSProject string

	// Email is the email address to use when creating an ACME account
	Email string

	// Staging use staging CA endpoints
	Staging bool

	// Bucket bucket to use for certstorage
	Bucket string
}

var logger *zap.Logger

func main() {
	logConf := zap.NewDevelopmentConfig()
	logger, _ = logConf.Build()
	ok, err := clingy.Environment{}.Run(context.Background(), func(cmds clingy.Commands) {
		logEnabled := cmds.Flag("log.debug", "log debug messages", false,
			clingy.Transform(strconv.ParseBool), clingy.Boolean,
		).(bool)
		if !logEnabled {
			logConf.Level.SetLevel(zap.InfoLevel)
		}

		c := &certmagicConfig{}
		setupGlobalCertmagicConfig(cmds, c)

		cmds.Group("cert", "certificate commands", func() {
			cmds.New("list", "list certificates in storage", &cmdList{config: c})
			cmds.New("show", "show a certificate from storage", &cmdShow{config: c})
			cmds.New("obtain", "obtains and stores a certificate for a domain, noop if cert already in storage", &cmdObtain{config: c})
			cmds.New("renew", "renews and stores the certificate for a domain", &cmdRenew{config: c})
			cmds.New("revoke", "revokes the certificate for a domain and deletes it from storage", &cmdRevoke{config: c})
		})
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
	}
	if !ok || err != nil {
		_ = logger.Sync()
		os.Exit(1)
	}
	_ = logger.Sync()
}

type cmdList struct {
	config *certmagicConfig
}

func (cmd *cmdList) Setup(params clingy.Parameters) {
}

func (cmd *cmdList) Execute(ctx context.Context) error {
	// prefix must be removed from bucket for gcs json api list operations
	bucket, prefix, found := strings.Cut(cmd.config.Bucket, "/")
	if found {
		// Make sure prefix has trailing slash
		prefix = strings.TrimSuffix(prefix, "/") + "/"
	}
	cmd.config.Bucket = bucket

	magic, err := configureCertMagic(ctx, cmd.config, true, true)
	if err != nil {
		return err
	}
	defer certmagic.CleanUpOwnLocks(ctx, logger)

	return listCerts(ctx, prefix, magic)
}

type cmdShow struct {
	config *certmagicConfig
	name   string
}

func (cmd *cmdShow) Setup(params clingy.Parameters) {
	cmd.config.Staging = params.Flag("staging", "Use staging CA endpoints", false,
		clingy.Transform(strconv.ParseBool), clingy.Boolean,
	).(bool)
	cmd.name = params.Arg("name", "hostname to show certificate for (example.com)").(string)
}

func (cmd *cmdShow) Execute(ctx context.Context) error {
	magic, err := configureCertMagic(ctx, cmd.config, true, true)
	if err != nil {
		return err
	}
	cert, err := magic.CacheManagedCertificate(ctx, cmd.name)
	if err != nil {
		return err
	}
	result, err := certinfo.CertificateText(cert.Leaf)
	if err != nil {
		return err
	}
	fmt.Print(result)
	return nil
}

type cmdObtain struct {
	config      *certmagicConfig
	name        string
	gPublicCA   bool
	letsEncrypt bool
}

func (cmd *cmdObtain) Setup(params clingy.Parameters) {
	setupCommonFlags(params, cmd.config)
	cmd.gPublicCA = params.Flag("gpublicca", "obtain certificate from Google Public CA", true,
		clingy.Transform(strconv.ParseBool), clingy.Boolean,
	).(bool)
	cmd.letsEncrypt = params.Flag("letsencrypt", "obtain certificate from LetsEncrypt", true,
		clingy.Transform(strconv.ParseBool), clingy.Boolean,
	).(bool)
	cmd.name = params.Arg("name", "hostname to obtain certificate for (*.example.com,www.example.com)").(string)
}

func (cmd *cmdObtain) Execute(ctx context.Context) error {
	if cmd.config.Email == "" {
		return fmt.Errorf("email required")
	}
	magic, err := configureCertMagic(ctx, cmd.config, cmd.gPublicCA, cmd.letsEncrypt)
	if err != nil {
		return err
	}
	defer certmagic.CleanUpOwnLocks(ctx, logger)
	return magic.ObtainCertSync(ctx, cmd.name)
}

type cmdRenew struct {
	config *certmagicConfig
	name   string
	force  bool
}

func (cmd *cmdRenew) Setup(params clingy.Parameters) {
	setupCommonFlags(params, cmd.config)
	cmd.force = params.Flag("force", "force renew when not close to expiring", false,
		clingy.Transform(strconv.ParseBool), clingy.Boolean,
	).(bool)
	cmd.name = params.Arg("name", "hostname to renew certificate for (*.example.com,www.example.com)").(string)
}

func (cmd *cmdRenew) Execute(ctx context.Context) error {
	if cmd.config.Email == "" {
		return fmt.Errorf("email required")
	}
	magic, err := configureCertMagic(ctx, cmd.config, true, true)
	if err != nil {
		return err
	}
	defer certmagic.CleanUpOwnLocks(ctx, logger)
	return magic.RenewCertSync(ctx, cmd.name, cmd.force)
}

type cmdRevoke struct {
	config      *certmagicConfig
	reason      int
	gPublicCA   bool
	letsEncrypt bool
	name        string
}

func (cmd *cmdRevoke) Setup(params clingy.Parameters) {
	setupCommonFlags(params, cmd.config)
	cmd.gPublicCA = params.Flag("gpublicca", "revoke certificate from Google Public CA", true,
		clingy.Transform(strconv.ParseBool), clingy.Boolean,
	).(bool)
	cmd.letsEncrypt = params.Flag("letsencrypt", "revoke certificate from LetsEncrypt", true,
		clingy.Transform(strconv.ParseBool), clingy.Boolean,
	).(bool)
	cmd.name = params.Arg("name", "hostname to revoke certificate for (*.example.com,www.example.com)").(string)
	cmd.reason = params.Arg("reason", "reason for certificate revocation (unspecified, keyCompromise, affiliationChanged, superseded, cessationOfOperation, priviledgeWithdrawn, aACompromise)", clingy.Transform(parseReason)).(int)
}

func (cmd *cmdRevoke) Execute(ctx context.Context) error {
	if cmd.config.Email == "" {
		return fmt.Errorf("email required")
	}
	magic, err := configureCertMagic(ctx, cmd.config, cmd.gPublicCA, cmd.letsEncrypt)
	if err != nil {
		return err
	}
	// We have to call PreCheck to set email on the Issuer
	for i, issuer := range magic.Issuers {
		check, ok := issuer.(certmagic.PreChecker)
		if !ok {
			return fmt.Errorf("issuer %d (%s) is not a PreChecker", i, issuer)
		}
		// Ignore error, we're only calling PreCheck for the setEmail side effect
		_ = check.PreCheck(ctx, []string{cmd.name}, false)
	}
	return magic.RevokeCert(ctx, cmd.name, cmd.reason, true)
}

func setupGlobalCertmagicConfig(f clingy.Flags, config *certmagicConfig) {
	config.KeyFile = f.Flag("keyfile", "path to service account key file (permissions to use Google's Cloud Storage, Certificate Manager Public CA and Cloud DNS)", "").(string)
	config.Bucket = f.Flag("bucket", "bucket to use for certificate storage with optional prefix (bucket/prefix)", "").(string)
}

func setupCommonFlags(f clingy.Flags, config *certmagicConfig) {
	config.GCloudDNSProject = f.Flag("dnsproject", "a project where the Google Cloud DNS zone exists", "").(string)
	config.Email = f.Flag("email", "email address to use when creating an ACME account", "").(string)
	config.Staging = f.Flag("staging", "Use staging CA endpoints", false,
		clingy.Transform(strconv.ParseBool), clingy.Boolean,
	).(bool)
}

func configureCertMagic(ctx context.Context, config *certmagicConfig, gPublicCA bool, letsEncrypt bool) (*certmagic.Config, error) {
	jsonKey, err := os.ReadFile(config.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("unable to read cert-magic-key-file: %w", err)
	}
	cs, err := certstorage.NewGCS(ctx, logger, jsonKey, config.Bucket)
	if err != nil {
		return nil, fmt.Errorf("initializing certstorage: %w", err)
	}
	certmagic.Default.Storage = cs
	certmagic.Default.Logger = logger

	// Enabling the DNS challenge disables the other challenges for that
	// certmagic.ACMEIssuer instance.
	s := &certmagic.DNS01Solver{
		DNSProvider: &googleclouddns.Provider{
			Project:            config.GCloudDNSProject,
			ServiceAccountJSON: config.KeyFile,
		},
	}

	googleCA := gpublicca.New(certmagic.NewACMEIssuer(&certmagic.Default, certmagic.ACMEIssuer{
		CA:                   gpublicca.GooglePublicCAProduction,
		DisableHTTPChallenge: true,
		DNS01Solver:          s,
		Logger:               logger,
		Email:                config.Email,
		Agreed:               true,
	}), jsonKey)
	letsEncryptCA := certmagic.NewACMEIssuer(&certmagic.Default, certmagic.ACMEIssuer{
		CA:                   certmagic.LetsEncryptProductionCA,
		DisableHTTPChallenge: true,
		DNS01Solver:          s,
		Logger:               logger,
		Email:                config.Email,
		Agreed:               true,
	})

	if config.Staging {
		googleCA.CA = gpublicca.GooglePublicCAStaging
		letsEncryptCA.CA = certmagic.LetsEncryptStagingCA
	}

	issuers := []certmagic.Issuer{}
	if gPublicCA {
		issuers = append(issuers, googleCA)
	}
	if letsEncrypt {
		issuers = append(issuers, letsEncryptCA)
	}
	certmagic.Default.Issuers = issuers

	return certmagic.NewDefault(), nil
}

func listCerts(ctx context.Context, prefix string, magic *certmagic.Config) error {
	log := logger.Sugar()
	previousIssuer := ""

	keys, err := magic.Storage.List(ctx, prefix+"certificates/", true)
	if err != nil {
		return err
	}

	for _, certKey := range keys {
		if path.Ext(certKey) != ".crt" {
			continue
		}

		certFile, err := magic.Storage.Load(ctx, certKey)
		if err != nil {
			log.Errorf("loading certificate file %s: %v", certKey, err)
			continue
		}
		block, _ := pem.Decode(certFile)
		if block == nil || block.Type != "CERTIFICATE" {
			log.Errorf("certificate file %s does not contain PEM-encoded certificate", certKey)
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Errorf("certificate file %s is malformed; error parsing PEM: %v", certKey, err)
			continue
		}
		if previousIssuer != cert.Issuer.String() {
			fmt.Printf("%v\n", cert.Issuer)
			previousIssuer = cert.Issuer.String()
		}

		// Expired
		if time.Now().After(cert.NotAfter) {
			color.Set(color.FgRed)
		}
		fmt.Printf("\t%v %v\n", cert.NotAfter, cert.Subject)
		color.Unset()
	}
	return nil
}

type reasonCode int

const (
	unspecified reasonCode = iota
	keyCompromise
	caCompromise
	affiliationChanged
	superseded
	cessationOfOperation
	certificateHold
	_
	removeFromCRL
	privilegeWithdrawn
	aACompromise

	unspecifiedName          = "unspecified"
	keyCompromiseName        = "keycompromise"
	caCompromiseName         = "cacompromise"
	affiliationChangedName   = "afflicationchanged"
	supersededName           = "superseded"
	cessationOfOperationName = "cessationofoperation"
	certificateHoldName      = "certificatehold"
	removeFromCRLName        = "removefromcrl"
	privilegeWithdrawnName   = "privilegewithdrawn"
	aACompromiseName         = "aacompromise"
)

func parseReason(name string) (int, error) {
	var r reasonCode
	switch strings.ToLower(name) {
	case unspecifiedName:
		r = unspecified
	case keyCompromiseName:
		r = keyCompromise
	case caCompromiseName:
		r = caCompromise
	case affiliationChangedName:
		r = affiliationChanged
	case supersededName:
		r = superseded
	case cessationOfOperationName:
		r = cessationOfOperation
	case certificateHoldName:
		r = certificateHold
	case removeFromCRLName:
		r = removeFromCRL
	case privilegeWithdrawnName:
		r = privilegeWithdrawn
	case aACompromiseName:
		r = aACompromise

	default:
		return 0, fmt.Errorf("invalid reason")
	}
	return int(r), nil
}
