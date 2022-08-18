// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package satellitelist

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spacemonkeygo/monkit/v3"
	"github.com/zeebo/errs"

	"storj.io/common/rpc"
	"storj.io/common/storj"
)

var mon = monkit.Package()

// ErrAllowedSatelliteList is an error class for allowed satellite list errors.
var ErrAllowedSatelliteList = errs.Class("allowed satellite list")

// LoadSatelliteURLs takes a list of configuration paths and returns a list of
// satellites URLs suitable for calling ("*Database).SetAllowedSatellites().
// ConfigValues may be satellite address URLs with a node id.  Alternatively,
// ConfigValues may be local or HTTP(S) files which contain one satellite address per line,
// the same format as https://www.storj.io/dcs-satellites.  HasNodeList indicates
// if any configValue is a node address list, indicating it should be polled for updates.
func LoadSatelliteURLs(ctx context.Context, configValues []string) (satMap map[storj.NodeURL]struct{}, hasNodeList bool, err error) {
	defer mon.Task()(&ctx)(&err)

	satMap = make(map[storj.NodeURL]struct{})
	for _, c := range configValues {
		c = strings.TrimSpace(c)
		if strings.HasPrefix(c, "http") {
			hasNodeList = true
			fileContent, err := getHTTPList(ctx, c)
			if err != nil {
				return satMap, hasNodeList, err
			}
			err = readSatelliteList(fileContent, satMap)
			if err != nil {
				return satMap, hasNodeList, ErrAllowedSatelliteList.Wrap(err)
			}
		} else if _, err := os.Stat(c); err == nil {
			hasNodeList = true
			bodyBytes, err := os.ReadFile(c)
			if err != nil {
				return satMap, hasNodeList, ErrAllowedSatelliteList.Wrap(err)
			}
			err = readSatelliteList(bodyBytes, satMap)
			if err != nil {
				return satMap, hasNodeList, ErrAllowedSatelliteList.Wrap(err)
			}
		} else if nodeURL, err := ParseSatelliteURL(c); err == nil {
			satMap[nodeURL] = struct{}{}
		} else {
			return satMap, hasNodeList, ErrAllowedSatelliteList.New("unknown config value '%s'", c)
		}
	}
	return satMap, hasNodeList, nil
}

// readSatelliteList populates a map from a newline separated list of Satellite
// addresses.  Empty lines or lines starting with '#' (comments) are ignored.
func readSatelliteList(input []byte, satellites map[storj.NodeURL]struct{}) (err error) {
	for _, line := range bytes.Split(input, []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		nodeURL, err := ParseSatelliteURL(string(line))
		if err != nil {
			return err // already wrapped
		}
		satellites[nodeURL] = struct{}{}
	}
	return nil
}

// getHTTPList downloads and returns bytes served under url and any error
// encountered.
func getHTTPList(ctx context.Context, url string) (_ []byte, err error) {
	defer mon.Task()(&ctx)(&err)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, ErrAllowedSatelliteList.Wrap(err)
	}
	res, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return nil, ErrAllowedSatelliteList.Wrap(err)
	}
	defer func() { err = errs.Combine(err, ErrAllowedSatelliteList.Wrap(res.Body.Close())) }()

	if res.StatusCode != 200 {
		return nil, ErrAllowedSatelliteList.New("HTTP failed with HTTP status %d", res.StatusCode)
	}
	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, ErrAllowedSatelliteList.Wrap(err)
	}
	return bodyBytes, nil
}

// ParseSatelliteURL parses a Satellite address and returns the URL.
func ParseSatelliteURL(s string) (id storj.NodeURL, err error) {
	url, err := storj.ParseNodeURL(s)
	if err != nil {
		return storj.NodeURL{}, ErrAllowedSatelliteList.Wrap(err)
	}

	if url.ID.IsZero() {
		nodeID, found := rpc.KnownNodeID(url.Address)
		if !found {
			return storj.NodeURL{}, ErrAllowedSatelliteList.New("unknown satellite %q", s)
		}
		url.ID = nodeID
	}

	return url, nil
}
