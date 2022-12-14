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

	// TwitterImage and OgImage are, when not empty, valid paths to an image
	// object and intended to be used as links to image previews when a
	// linksharing URL pointing to an image is shared on Twitter and/or
	// Facebook.
	TwitterImage, OgImage string

	ArchivePath      string
	ShowViewContents bool
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

	// ConnectionPool is configuration for RPC connection pool options.
	ConnectionPool ConnectionPoolConfig

	// UseQOSAndCC indicates if congestion control and QOS settings from BackgroundDialer should be used.
	UseQosAndCC bool

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
	static                 http.Handler
	redirectHTTPS          bool
	landingRedirect        string
	uplink                 *uplink.Config
	trustedClientIPsList   trustedip.List
	standardRendersContent bool
	standardViewsHTML      bool
	archiveRanger          func(ctx context.Context, project *uplink.Project, bucket, key, path string, canReturnGzip bool) (_ ranger.Ranger, isGzip bool, _ error)
}

// NewHandler creates a new link sharing HTTP handler.
func NewHandler(log *zap.Logger, mapper *objectmap.IPDB, txtRecords *TXTRecords, authClient *authclient.AuthClient, config Config) (*Handler, error) {
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
	if !config.UseQosAndCC {
		// an unset DialContext defaults to BackgroundDialer's CC and QOS settings
		uplinkConfig.DialContext = (&net.Dialer{}).DialContext
	}

	err = transport.SetConnectionPool(context.TODO(), uplinkConfig,
		rpcpool.New(rpcpool.Options(config.ConnectionPool)))
	if err != nil {
		return nil, err
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
		static:                 http.StripPrefix("/static/", http.FileServer(http.Dir(config.StaticSourcesPath))),
		landingRedirect:        config.LandingRedirectTarget,
		redirectHTTPS:          config.RedirectHTTPS,
		uplink:                 uplinkConfig,
		trustedClientIPsList:   trustedClientIPs,
		standardRendersContent: config.StandardRendersContent,
		standardViewsHTML:      config.StandardViewsHTML,
		archiveRanger:          defaultArchiveRanger,
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
		status = http.StatusTooManyRequests
		message = "Oops! Rate limited due too many request."
		skipLog = true
	case errors.Is(handlerErr, context.Canceled) && errors.Is(ctx.Err(), context.Canceled):
		status = errdata.HTTPStatusClientClosedRequest
		message = "Client closed request."
		skipLog = true
	case httpranger.ErrInvalidRange.Has(handlerErr):
		status = http.StatusRequestedRangeNotSatisfiable
		message = "Range header isn't compatible with path query."
		skipLog = true
	default:
		status = errdata.GetStatus(handlerErr, status)
		switch status {
		case http.StatusForbidden:
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
	handler.renderTemplate(w, "error.html", pageData{Data: message, Title: "Error"})
}

func (handler *Handler) renderTemplate(w http.ResponseWriter, template string, data pageData) {
	data.Base = strings.TrimSuffix(handler.urlBases[0].String(), "/")
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
	case handler.redirectHTTPS && r.URL.Scheme == "http":
		u, err := url.ParseRequestURI(r.RequestURI)
		if err != nil {
			return errdata.WithStatus(errs.New("invalid request URI"), http.StatusInternalServerError)
		}
		u.Scheme = "https"
		http.Redirect(w, r, u.String(), http.StatusPermanentRedirect)
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
	_, err = w.Write([]byte("okay"))
	return err
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
