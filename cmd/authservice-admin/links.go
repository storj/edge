// Copyright (C) 2023 Storj Labs, Inc.
// See LICENSE for copying information.

package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/jtolio/eventkit"
	"github.com/zeebo/clingy"
	"github.com/zeebo/errs"
	"golang.org/x/sync/errgroup"

	"storj.io/common/storj"
	"storj.io/edge/internal/authadminclient"
	"storj.io/edge/internal/satelliteadminclient"
	"storj.io/edge/pkg/auth/authdb"
	"storj.io/edge/pkg/hashreader"
	"storj.io/edge/pkg/sharedlink"
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
		return errs.New("get access key: %w", authAccessKeyError(err))
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
	URL               string `json:"url"`
	Name              string `json:"name"`
	Email             string `json:"email"`
	PaidTier          bool   `json:"paid_tier"`
	ContentHashSHA256 string `json:"content_hash_sha256,omitempty"`
	Error             string `json:"error,omitempty"`
}

type cmdLinksRevoke struct {
	output          string
	inputFilePath   string
	freezeAccounts  bool
	hashContents    bool
	authAdminClient *authadminclient.Client
	satAdminClients map[string]*satelliteadminclient.Client
}

func (cmd *cmdLinksRevoke) Setup(params clingy.Parameters) {
	cmd.authAdminClient = newAuthAdminClient(params)
	cmd.satAdminClients = mustSatAdminClients(params)
	cmd.freezeAccounts = params.Flag("freeze-accounts", "freeze free-tier user accounts", true,
		clingy.Transform(strconv.ParseBool), clingy.Boolean,
	).(bool)
	cmd.hashContents = params.Flag("hash-contents", "hash link contents and send an event if events address configured", true,
		clingy.Transform(strconv.ParseBool), clingy.Boolean,
	).(bool)
	cmd.output = params.Flag("output", "output format (either json or leave empty to output as text)", "", clingy.Short('o')).(string)
	cmd.inputFilePath = params.Arg("input", "input file path").(string)
}

func (cmd *cmdLinksRevoke) Execute(ctx context.Context) error {
	urls, err := scanURLs(cmd.inputFilePath)
	if err != nil {
		return err
	}

	results := make([]revokeResult, len(urls))

	for i, url := range urls {
		results[i].URL = url

		if cmd.hashContents {
			hb, err := hashContents(ctx, url)
			if err != nil {
				results[i].Error = errs.New("hash contents: %w", err).Error()
				continue
			}

			if hb != nil {
				results[i].ContentHashSHA256 = hex.EncodeToString(hb)

				ek.Event("revokedlink",
					eventkit.String("link", url),
					eventkit.String("hash-sha256", hex.EncodeToString(hb)))
			}
		}

		link, err := sharedlink.Parse(url)
		if err != nil {
			results[i].Error = errs.New("parse link: %w", err).Error()
			continue
		}

		if err := cmd.revokeAccess(ctx, link.AccessKey, &results[i]); err != nil {
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

func (cmd *cmdLinksRevoke) revokeAccess(ctx context.Context, accessKey string, result *revokeResult) error {
	authRecord, err := cmd.authAdminClient.Resolve(ctx, accessKey)
	if err != nil {
		return errs.New("get access key: %w", authAccessKeyError(err))
	}

	satelliteNodeURL, err := storj.ParseNodeURL(authRecord.SatelliteAddress)
	if err != nil {
		return errs.New("parse node url: %w", err)
	}

	satAdminClient, ok := cmd.satAdminClients[satelliteNodeURL.Address]
	if !ok {
		return errs.New("could not find satellite admin address for %q", satelliteNodeURL.Address)
	}

	var eg errs.Group

	apiKeyResp, err := satAdminClient.GetAPIKey(ctx, authRecord.APIKey)
	if err != nil {
		if !errs.Is(err, satelliteadminclient.ErrNotFound) {
			return errs.New("get api key: %w", err)
		}
	} else {
		result.Name = apiKeyResp.Owner.FullName
		result.Email = apiKeyResp.Owner.Email
		result.PaidTier = apiKeyResp.Owner.PaidTier

		eg.Add(satAdminClient.DeleteAPIKey(ctx, authRecord.APIKey))

		if !apiKeyResp.Owner.PaidTier && cmd.freezeAccounts {
			eg.Add(satAdminClient.ViolationFreezeAccount(ctx, apiKeyResp.Owner.Email))
		}
	}

	eg.Add(cmd.deleteAuthRecords(ctx, accessKey))

	return eg.Err()
}

func (cmd *cmdLinksRevoke) deleteAuthRecords(ctx context.Context, accessKey string) error {
	// note: accessKey could be an access grant, so we need to check first.
	if len(accessKey) != authdb.EncKeySizeEncoded {
		return nil
	}
	if err := cmd.authAdminClient.Delete(ctx, accessKey); err != nil {
		return errs.New("error deleting access keys on authservice nodes: %w. Please run `authservice-admin record delete %s --delete-api-key=false` to clean these up", err, accessKey)
	}
	return nil
}

func hashContents(ctx context.Context, url string) ([]byte, error) {
	rawURL, err := rawLinkURL(url)
	if err != nil {
		return nil, err
	}

	logger.Printf("hashing contents of %s\n", rawURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL.String(), nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode >= 500 {
			return nil, errs.New("unexpected status: %s", resp.Status)
		}

		logger.Printf("%s appears to be offline (%s), skipping hashing", rawURL, resp.Status)
		return nil, nil
	}

	hr := hashreader.New(resp.Body, sha256.New())
	_, err = io.Copy(io.Discard, hr)
	if err != nil {
		return nil, err
	}

	hashSum := hr.Sum()

	logger.Printf("sha256 sum of %s: %s", rawURL, hex.EncodeToString(hashSum))

	return hashSum, nil
}

// rawLinkURL modifies a linksharing URL from /s/ to /raw/ format without any
// query values. Anything else like S3 presigned URLs are returned parsed
// without changes.
func rawLinkURL(rawURL string) (*url.URL, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}

	path := u.EscapedPath()
	if strings.HasPrefix(path, "/s/") {
		u.Path = "/raw/" + path[len("/s/"):]
		u.RawQuery = ""
	}

	return u, nil
}

func printRevokeResults(results []revokeResult) {
	for _, r := range results {
		fmt.Println(r.URL)
		fmt.Println("---")
		printFixed("Name:", r.Name)
		printFixed("Email:", r.Email)
		printFixed("Paid tier:", strconv.FormatBool(r.PaidTier))
		if r.ContentHashSHA256 != "" {
			printFixed("Content hash SHA-256:", r.ContentHashSHA256)
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
