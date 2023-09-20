// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package sharing

import (
	"context"
	"errors"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jtolio/eventkit"
	"github.com/spacemonkeygo/monkit/v3"
	"github.com/zeebo/errs"
	"go.uber.org/zap"

	"storj.io/common/ranger"
	"storj.io/common/ranger/httpranger"
	"storj.io/common/rpc/rpcpool"
	"storj.io/gateway-mt/pkg/authclient"
	"storj.io/gateway-mt/pkg/errdata"
	"storj.io/gateway-mt/pkg/linksharing/objectmap"
	"storj.io/gateway-mt/pkg/trustedip"
	"storj.io/private/version"
	"storj.io/uplink"
	"storj.io/uplink/private/transport"
	"storj.io/zipper"
)

var (
	mon = monkit.Package()
	ek  = eventkit.Package()
)

// pageData is the type that is passed to the template rendering engine.
type pageData struct {
	Data  interface{} // data to provide to the page
	Title string      // <title> for the page

	// because we are serving data on someone else's domain, for our
	// branded pages like file listing and the map view, all static assets
	// must use an absolute url. this is the base url they are all based off
	// of. automatically filled in by renderTemplate.
	Base string

	// This is the current Linksharing version hashed. It's useful to append
	// to static file paths when including them in the HTML, so that if the file
	// was modified in a new release then the browser will re-fetch the file.
	// Browsers often cache static files with or without cache headers, unless
	// you use no-cache in Cache-Control so it forces to check back with
	// the server if the file was modified. To get a long caching period and
	// no need to check back to the server, we add a version hash to each
	// static file URL so it's re-fetched when we deploy a new release.
	//
	// TODO: a better way to do this would be to have files named with the
	// commit hash, but we need a build system to do this.
	//
	// References:
	//   * https://developer.chrome.com/docs/lighthouse/performance/uses-long-cache-ttl/
	//   * https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control#caching_static_assets_with_cache_busting
	VersionHash string

	// TwitterImage and OgImage are, when not empty, valid paths to an image
	// object and intended to be used as links to image previews when a
	// linksharing URL pointing to an image is shared on Twitter and/or
	// Facebook.
	TwitterImage, OgImage string

	ArchivePath      string
	ShowViewContents bool

	// Download button should be disabled for files the sharing access doesn't
	// allow to download.
	AllowDownload bool
}

// Config specifies the handler configuration.
type Config struct {
	// URLBases is the collection of potential base URLs of the link sharing
	// handler. The first one in the list is used to construct URLs returned
	// to clients. All should be a fully formed URL.
	URLBases []string

	// Templates location with html templates.
	Templates string

	// StaticSourcesPath is the path to where the web assets are located
	// on disk.
	StaticSourcesPath string

	// TXTRecordTTL is the duration for which an entry in the txtRecordCache is valid.
	TXTRecordTTL time.Duration

	// AuthServiceConfig contains configuration required to use the auth service to resolve
	// access key ids into access grants.
	AuthServiceConfig authclient.Config

	// DNS Server address, for TXT record lookup
	DNSServer string

	// RedirectHTTPS enables redirection to https://.
	RedirectHTTPS bool

	// LandingRedirectTarget is the url to redirect empty requests to.
	LandingRedirectTarget string

	// uplink Config settings
	Uplink *uplink.Config

	// SatelliteConnectionPool is configuration for satellite RPC connection pool options.
	SatelliteConnectionPool ConnectionPoolConfig

	// ConnectionPool is configuration for RPC connection pool options.
	ConnectionPool ConnectionPoolConfig

	// ClientTrustedIPsList is the list of client IPs which are trusted. These IPs
	// are usually from gateways, load balancers, etc., which expose the service
	// to the public internet. Trusting them implies that the service may use
	// information of the request (e.g. getting client, the originator of the
	// request, IP from headers).
	ClientTrustedIPsList []string

	// UseClientIPHeaders indicates that the HTTP headers `Forwarded`,
	// `X-Forwarded-Ip`, and `X-Real-Ip` (in this order) are used to get the
	// client IP before falling back of getting from the client request.
	//
	// When true it reads them only from the trusted IPs (ClientTrustedIPList) if
	// it isn't empty.
	UseClientIPHeaders bool

	// StandardRendersContent controls whether to enable standard (non-hosting)
	// requests to render content and not only download it.
	StandardRendersContent bool

	// StandardViewsHTML controls whether to serve HTML as text/html instead of
	// text/plain for standard (non-hosting) requests.
	StandardViewsHTML bool
}

// ConnectionPoolConfig is a config struct for configuring RPC connection pool options.
type ConnectionPoolConfig struct {
	Capacity       int
	KeyCapacity    int
	IdleExpiration time.Duration
}

// Handler implements the link sharing HTTP handler.
//
// architecture: Service
type Handler struct {
	log                    *zap.Logger
	urlBases               []*url.URL
	templates              *template.Template
	mapper                 *objectmap.IPDB
	txtRecords             *TXTRecords
	authClient             *authclient.AuthClient
	tierQuerying           *TierQueryingService
	static                 http.Handler
	redirectHTTPS          bool
	landingRedirect        string
	uplink                 *uplink.Config
	trustedClientIPsList   trustedip.List
	standardRendersContent bool
	standardViewsHTML      bool
	archiveRanger          func(ctx context.Context, project *uplink.Project, bucket, key, path string, canReturnGzip bool) (_ ranger.Ranger, isGzip bool, _ error)
	inShutdown             *int32
}

// NewHandler creates a new link sharing HTTP handler.
func NewHandler(log *zap.Logger, mapper *objectmap.IPDB, txtRecords *TXTRecords, authClient *authclient.AuthClient, tqs *TierQueryingService, inShutdown *int32, config Config) (*Handler, error) {
	bases := make([]*url.URL, 0, len(config.URLBases))
	for _, base := range config.URLBases {
		parsed, err := parseURLBase(base)
		if err != nil {
			return nil, err
		}
		bases = append(bases, parsed)
	}
	if len(bases) < 1 {
		return nil, errors.New("requires at least one url base")
	}

	templates, err := template.ParseGlob(filepath.Join(config.Templates, "*.html"))
	if err != nil {
		return nil, err
	}

	uplinkConfig := config.Uplink
	if uplinkConfig == nil {
		uplinkConfig = &uplink.Config{}
	}

	err = transport.SetConnectionPool(context.TODO(), uplinkConfig,
		rpcpool.New(rpcpool.Options{
			Name:           "default",
			Capacity:       config.ConnectionPool.Capacity,
			KeyCapacity:    config.ConnectionPool.KeyCapacity,
			IdleExpiration: config.ConnectionPool.IdleExpiration,
		}))
	if err != nil {
		return nil, err
	}

	if config.SatelliteConnectionPool != (ConnectionPoolConfig{}) {
		err = transport.SetSatelliteConnectionPool(context.TODO(), uplinkConfig,
			rpcpool.New(rpcpool.Options{
				Name:           "satellite",
				Capacity:       config.SatelliteConnectionPool.Capacity,
				KeyCapacity:    config.SatelliteConnectionPool.KeyCapacity,
				IdleExpiration: config.SatelliteConnectionPool.IdleExpiration,
			}))
		if err != nil {
			return nil, err
		}
	}

	var trustedClientIPs trustedip.List
	if config.UseClientIPHeaders {
		if len(config.ClientTrustedIPsList) > 0 {
			trustedClientIPs = trustedip.NewList(config.ClientTrustedIPsList...)
		} else {
			trustedClientIPs = trustedip.NewListTrustAll()
		}
	} else {
		trustedClientIPs = trustedip.NewListUntrustAll()
	}

	if authClient == nil {
		authClient = authclient.New(config.AuthServiceConfig)
	}

	if txtRecords == nil {
		dns, err := NewDNSClient(config.DNSServer)
		if err != nil {
			return nil, err
		}
		txtRecords = NewTXTRecords(config.TXTRecordTTL, dns, authClient)
	}

	return &Handler{
		log:                    log,
		urlBases:               bases,
		templates:              templates,
		mapper:                 mapper,
		txtRecords:             txtRecords,
		authClient:             authClient,
		tierQuerying:           tqs,
		static:                 cacheControlStatic(http.StripPrefix("/static/", http.FileServer(http.Dir(config.StaticSourcesPath)))),
		landingRedirect:        config.LandingRedirectTarget,
		redirectHTTPS:          config.RedirectHTTPS,
		uplink:                 uplinkConfig,
		trustedClientIPsList:   trustedClientIPs,
		standardRendersContent: config.StandardRendersContent,
		standardViewsHTML:      config.StandardViewsHTML,
		archiveRanger:          defaultArchiveRanger,
		inShutdown:             inShutdown,
	}, nil
}

// ServeHTTP handles link sharing requests.
func (handler *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer mon.Task()(&ctx)(nil)

	handlerErr := handler.serveHTTP(ctx, w, r)
	if handlerErr == nil {
		return
	}

	status := http.StatusInternalServerError
	message := "Internal server error. Please try again later."
	action := errdata.GetAction(handlerErr, "unknown")
	skipLog := false
	skipRendering := false
	switch {
	case errors.Is(handlerErr, uplink.ErrBucketNotFound):
		status = http.StatusNotFound
		message = "Oops! Bucket not found."
		skipLog = true
	case errors.Is(handlerErr, uplink.ErrObjectNotFound):
		status = http.StatusNotFound
		message = "Oops! Object not found."
		skipLog = true
	case errors.Is(handlerErr, uplink.ErrBucketNameInvalid):
		status = http.StatusBadRequest
		message = "Oops! Invalid bucket name."
		skipLog = true
	case errors.Is(handlerErr, uplink.ErrObjectKeyInvalid):
		status = http.StatusBadRequest
		message = "Oops! Invalid object key."
		skipLog = true
	case errors.Is(handlerErr, uplink.ErrPermissionDenied):
		status = http.StatusForbidden
		message = "Access denied."
		skipLog = true
	case errors.Is(handlerErr, uplink.ErrBandwidthLimitExceeded):
		status = http.StatusTooManyRequests
		message = "Oops! Bandwidth limit exceeded."
		skipLog = true
	case errors.Is(handlerErr, uplink.ErrTooManyRequests):
		http.Error(w, "429 Too Many Requests", http.StatusTooManyRequests)
		return
	case errors.Is(handlerErr, context.Canceled) && errors.Is(ctx.Err(), context.Canceled):
		status = errdata.HTTPStatusClientClosedRequest
		message = "Client closed request."
		skipLog = true
		// skip rendering to avoid "http2: stream closed" errors
		skipRendering = true
	case httpranger.ErrInvalidRange.Has(handlerErr):
		status = http.StatusRequestedRangeNotSatisfiable
		message = "Range header isn't compatible with path query."
		skipLog = true
	default:
		status = errdata.GetStatus(handlerErr, status)
		switch status {
		case http.StatusUnauthorized, http.StatusForbidden:
			message = "Access denied."
			skipLog = true
		case http.StatusNotFound:
			message = "Not found."
			skipLog = true
		case http.StatusBadRequest, http.StatusMethodNotAllowed:
			message = "Malformed request. Please try again."
			skipLog = true
		case http.StatusRequestedRangeNotSatisfiable:
			message = "Range header isn't compatible with path query."
			skipLog = true
		case http.StatusUnsupportedMediaType:
			message = "The zip archive is invalid or uses the wrong compression format."
			skipLog = true
		}
	}

	if !skipLog {
		handler.log.Error(
			"unable to handle request",
			zap.Error(handlerErr),
			zap.String("action", action),
			zap.Int("status_code", status),
		)
	} else {
		handler.log.Debug(
			"unable to handle request",
			zap.Error(handlerErr),
			zap.String("action", action),
			zap.Int("status_code", status),
		)
	}

	delete(w.Header(), "Content-Disposition")
	w.WriteHeader(status)
	if !skipRendering {
		handler.renderTemplate(w, "error.html", pageData{Data: message, Title: "Error"})
	}
}

func (handler *Handler) renderTemplate(w http.ResponseWriter, template string, data pageData) {
	data.Base = strings.TrimSuffix(handler.urlBases[0].String(), "/")
	data.VersionHash = version.Build.CommitHash
	err := handler.templates.ExecuteTemplate(w, template, data)
	if err != nil {
		handler.log.Error("error while executing template", zap.Error(err))
	}
}

func (handler *Handler) serveHTTP(ctx context.Context, w http.ResponseWriter, r *http.Request) (err error) {
	defer mon.Task()(&ctx)(&err)

	if r.Method == http.MethodOptions {
		// handle CORS pre-flight requests
		handler.cors(ctx, w, r)
		return nil
	} else if r.Method != http.MethodHead && r.Method != http.MethodGet {
		return errdata.WithStatus(errs.New("method not allowed"), http.StatusMethodNotAllowed)
	}
	handler.cors(ctx, w, r)

	ourDomain, err := isDomainOurs(r.Host, handler.urlBases)
	if err != nil {
		return err
	}

	if !ourDomain {
		return handler.handleHostingService(ctx, w, r)
	}

	switch {
	case handler.redirectHTTPS && r.TLS == nil:
		target := url.URL{Scheme: "https", Host: r.Host, Path: r.URL.EscapedPath(), RawQuery: r.URL.RawQuery}
		http.Redirect(w, r, target.String(), http.StatusPermanentRedirect)
		return nil
	case strings.HasPrefix(r.URL.Path, "/static/"):
		handler.static.ServeHTTP(w, r.WithContext(ctx))
		return nil
	case strings.HasPrefix(r.URL.Path, "/health/process"):
		return handler.healthProcess(ctx, w, r)
	case handler.landingRedirect != "" && (r.URL.Path == "" || r.URL.Path == "/"):
		http.Redirect(w, r, handler.landingRedirect, http.StatusSeeOther)
		return nil
	default:
		return handler.handleStandard(ctx, w, r)
	}
}

func (handler *Handler) cors(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, HEAD")
	w.Header().Set("Access-Control-Allow-Headers", "*")
}

func (handler *Handler) healthProcess(ctx context.Context, w http.ResponseWriter, r *http.Request) (err error) {
	defer mon.Task()(&ctx)(&err)
	if atomic.LoadInt32(handler.inShutdown) != 0 {
		http.Error(w, "down", http.StatusServiceUnavailable)
		return nil
	}
	_, err = w.Write([]byte("okay"))
	return err
}

func cacheControlStatic(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=15552000")
		h.ServeHTTP(w, r)
	})
}

func isDomainOurs(host string, bases []*url.URL) (bool, error) {
	for _, base := range bases {
		ours, err := compareHosts(host, base.Host)
		if err != nil {
			return false, err
		}
		if ours {
			return true, nil
		}
	}
	return false, nil
}

func compareHosts(addr1, addr2 string) (equal bool, err error) {
	host1, _, err1 := net.SplitHostPort(addr1)
	host2, _, err2 := net.SplitHostPort(addr2)

	if err1 != nil && strings.Contains(err1.Error(), "missing port in address") {
		host1 = addr1
	} else if err1 != nil {
		return false, err1
	}

	if err2 != nil && strings.Contains(err2.Error(), "missing port in address") {
		host2 = addr2
	} else if err2 != nil {
		return false, err2
	}

	if host1 != host2 {
		return false, nil
	}
	return true, nil
}

func parseURLBase(s string) (*url.URL, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, err
	}

	switch {
	case u.Scheme != "http" && u.Scheme != "https":
		return nil, errors.New("URL base must be http:// or https://")
	case u.Host == "":
		return nil, errors.New("URL base must contain host")
	case u.User != nil:
		return nil, errors.New("URL base must not contain user info")
	case u.RawQuery != "":
		return nil, errors.New("URL base must not contain query values")
	case u.Fragment != "":
		return nil, errors.New("URL base must not contain a fragment")
	}
	return u, nil
}

func defaultArchiveRanger(ctx context.Context, project *uplink.Project, bucket, key, path string, canReturnGzip bool) (ranger.Ranger, bool, error) {
	zip, err := zipper.OpenPack(ctx, project, bucket, key)
	if err != nil {
		return nil, false, err
	}
	fileInfo, err := zip.FileInfo(ctx, path)
	if err != nil {
		return nil, false, err
	}
	file, isGzip, size, err := fileInfo.OpenAsGzipOrUncompressed(ctx, canReturnGzip)
	if err != nil {
		return nil, false, err
	}
	return SimpleRanger(file.ReadCloser, size), isGzip, nil
}
