// Copyright (C) 2023 Storj Labs, Inc.
// See LICENSE for copying information.

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/zeebo/clingy"
	"github.com/zeebo/errs"
	"golang.org/x/sync/errgroup"

	"storj.io/common/storj"
	"storj.io/gateway-mt/internal/authadminclient"
	"storj.io/gateway-mt/internal/satelliteadminclient"
	"storj.io/gateway-mt/pkg/auth/authdb"
	"storj.io/gateway-mt/pkg/sharedlink"
)

type inspectResult struct {
	record
	URL    string `json:"url"`
	Online bool   `json:"online"`
	Error  string `json:"error,omitempty"`
}

type cmdLinksInspect struct {
	output          string
	inputFilePath   string
	authAdminClient *authadminclient.Client
	satAdminClients map[string]*satelliteadminclient.Client
}

func (cmd *cmdLinksInspect) Setup(params clingy.Parameters) {
	cmd.authAdminClient = newAuthAdminClient(params)
	cmd.satAdminClients = mustSatAdminClients(params)
	cmd.output = params.Flag("output", "output format (either json or leave empty to output as text)", "", clingy.Short('o')).(string)
	cmd.inputFilePath = params.Arg("input", "input file path").(string)
}

func (cmd *cmdLinksInspect) Execute(ctx context.Context) (err error) {
	urls, err := scanURLs(cmd.inputFilePath)
	if err != nil {
		return err
	}

	results := make([]inspectResult, len(urls))

	for i, url := range urls {
		results[i].URL = url

		online, err := isOnline(ctx, url)
		if err != nil {
			results[i].Error = err.Error()
			continue
		}
		results[i].Online = online

		if err := cmd.setRecords(ctx, url, &results[i]); err != nil {
			results[i].Error = err.Error()
		}
	}

	switch cmd.output {
	case "json":
		return json.NewEncoder(os.Stdout).Encode(&results)
	default:
		printInspectResults(results)
		return nil
	}
}

func (cmd *cmdLinksInspect) setRecords(ctx context.Context, url string, result *inspectResult) error {
	link, err := sharedlink.Parse(url)
	if err != nil {
		return errs.New("parse link: %w", err)
	}

	authRecord, err := cmd.authAdminClient.Resolve(ctx, link.AccessKey)
	if err != nil {
		return errs.New("resolve: %w", err)
	}

	result.AuthRecord = authRecord

	if cmd.satAdminClients != nil {
		satelliteNodeURL, err := storj.ParseNodeURL(authRecord.SatelliteAddress)
		if err != nil {
			return errs.New("parse node url: %w", err)
		}

		satAdminClient, ok := cmd.satAdminClients[satelliteNodeURL.Address]
		if !ok {
			return errs.New("could not find satellite admin address for %q", satelliteNodeURL.Address)
		}

		apiKeyResp, err := satAdminClient.GetAPIKey(ctx, authRecord.APIKey)
		if err != nil {
			return errs.New("get api key: %w", satAPIKeyError(err))
		}

		result.SatRecord = apiKeyResp
	}

	return nil
}

func printInspectResults(results []inspectResult) {
	for _, r := range results {
		fmt.Println(r.URL)
		fmt.Println("---")
		printFixed("Online:", strconv.FormatBool(r.Online))
		if r.Error != "" {
			printFixed("Error:", r.Error)
		}
		printRecord(r.record)
		fmt.Println("")
	}
}

// isOnline checks multiple HTTP methods to see if the link appears online.
//
// We consider a link is online if any one of HEAD or GET requests returns a
// good response. We do this because S3 presigned links are signed for a
// particular method only, so we can't always do a HEAD request reliably.
func isOnline(ctx context.Context, url string) (bool, error) {
	methods := []string{http.MethodHead, http.MethodGet}
	responses := make([]bool, len(methods))
	var group errgroup.Group
	for i, method := range methods {
		i := i
		method := method
		group.Go(func() error {
			req, err := http.NewRequestWithContext(ctx, method, url, nil)
			if err != nil {
				return err
			}

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return err
			}
			_ = resp.Body.Close()

			switch {
			case resp.StatusCode == http.StatusOK:
				responses[i] = true
			case resp.StatusCode >= 500:
				return errs.New("unexpected status: %s", resp.Status)
			default:
				responses[i] = false
			}

			return nil
		})
	}
	if err := group.Wait(); err != nil {
		return false, err
	}
	for _, online := range responses {
		if online {
			return true, nil
		}
	}
	return false, nil
}

type revokeResult struct {
	URL       string    `json:"url"`
	Name      string    `json:"name"`
	Email     string    `json:"email"`
	PaidTier  bool      `json:"paid_tier"`
	RemovedAt time.Time `json:"removed_at,omitempty"`
	Error     string    `json:"error,omitempty"`
}

type cmdLinksRevoke struct {
	output               string
	inputFilePath        string
	setProjectLimitsZero bool
	authAdminClient      *authadminclient.Client
	satAdminClients      map[string]*satelliteadminclient.Client
}

func (cmd *cmdLinksRevoke) Setup(params clingy.Parameters) {
	cmd.authAdminClient = newAuthAdminClient(params)
	cmd.satAdminClients = mustSatAdminClients(params)
	cmd.setProjectLimitsZero = params.Flag("set-project-limits-zero", "set project limits to zero for free-tier user's projects", true,
		clingy.Transform(strconv.ParseBool), clingy.Boolean,
	).(bool)
	cmd.output = params.Flag("output", "output format (either json or leave empty to output as text)", "", clingy.Short('o')).(string)
	cmd.inputFilePath = params.Arg("input", "input file path").(string)
}

func (cmd *cmdLinksRevoke) Execute(ctx context.Context) (err error) {
	urls, err := scanURLs(cmd.inputFilePath)
	if err != nil {
		return err
	}

	results := make([]revokeResult, len(urls))

	for i, url := range urls {
		results[i].URL = url

		if err := cmd.revokeURL(ctx, url, &results[i]); err != nil {
			results[i].Error = err.Error()
		}
	}

	switch cmd.output {
	case "json":
		return json.NewEncoder(os.Stdout).Encode(&results)
	default:
		printRevokeResults(results)
		return nil
	}
}

func (cmd *cmdLinksRevoke) revokeURL(ctx context.Context, uri string, result *revokeResult) error {
	link, err := sharedlink.Parse(uri)
	if err != nil {
		return errs.New("parse link: %w", err)
	}

	authRecord, err := cmd.authAdminClient.Resolve(ctx, link.AccessKey)
	if err != nil {
		return errs.New("resolve: %w", err)
	}

	satelliteNodeURL, err := storj.ParseNodeURL(authRecord.SatelliteAddress)
	if err != nil {
		return errs.New("parse node url: %w", err)
	}

	satAdminClient, ok := cmd.satAdminClients[satelliteNodeURL.Address]
	if !ok {
		return errs.New("could not find satellite admin address for %q", satelliteNodeURL.Address)
	}

	apiKeyResp, err := satAdminClient.GetAPIKey(ctx, authRecord.APIKey)
	if err != nil {
		return errs.New("get api key: %w", satAPIKeyError(err))
	}

	result.Name = apiKeyResp.Owner.FullName
	result.Email = apiKeyResp.Owner.Email
	result.PaidTier = apiKeyResp.Owner.PaidTier

	// if we're revoking access to a free tier owner, set all their project limits to zero.
	if !apiKeyResp.Owner.PaidTier && cmd.setProjectLimitsZero {
		userResp, err := satAdminClient.GetUser(ctx, apiKeyResp.Owner.Email)
		if err != nil {
			return errs.New("get user: %w", err)
		}

		limits := make(url.Values)
		limits.Set("usage", "0")
		limits.Set("bandwidth", "0")
		limits.Set("rate", "0")
		limits.Set("buckets", "0")
		limits.Set("burst", "0")
		limits.Set("segments", "0")

		for _, project := range userResp.Projects {
			if err := satAdminClient.SetProjectLimits(ctx, project.ID.String(), limits); err != nil {
				return errs.New("set project limits: %w", err)
			}
		}
	}

	if err := satAdminClient.DeleteAPIKey(ctx, authRecord.APIKey); err != nil {
		return errs.New("delete api key: %w", satAPIKeyError(err))
	}

	// note: accessKey could be an access grant, so we need to check first.
	if len(link.AccessKey) == authdb.EncKeySizeEncoded {
		if err := cmd.authAdminClient.Delete(ctx, link.AccessKey); err != nil {
			return errs.New("api key was deleted on satellite, but errors deleting on authservice nodes: %w. Please run `authservice-admin record delete %s --delete-api-key=false` to clean these up", err, link.AccessKey)
		}
	}

	result.RemovedAt = time.Now().UTC()

	return nil
}

func printRevokeResults(results []revokeResult) {
	for _, r := range results {
		fmt.Println(r.URL)
		fmt.Println("---")
		printFixed("Name:", r.Name)
		printFixed("Email:", r.Email)
		printFixed("Paid tier:", strconv.FormatBool(r.PaidTier))
		if !r.RemovedAt.IsZero() {
			printFixed("Removed at:", r.RemovedAt.Format(time.RFC3339))
		}
		if r.Error != "" {
			printFixed("Error:", r.Error)
		}
		fmt.Println("")
	}
}

func scanURLs(name string) ([]string, error) {
	file, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = file.Close()
	}()

	var urls []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) != "" {
			urls = append(urls, scanner.Text())
		}
	}
	if scanner.Err() != nil {
		return nil, scanner.Err()
	}

	return urls, nil
}
