// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package auth

import (
	"bytes"
	"context"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/zeebo/errs"

	"storj.io/common/rpc"
	"storj.io/common/storj"
)

// ErrAllowedSatelliteList is an error class for allowed satellite list errors.
var ErrAllowedSatelliteList = errs.Class("allowed satellite list")

// LoadSatelliteIDs takes a list of configuration paths and returns a list of
// satellites IDs suitable for calling ("*Database).SetAllowedSatellites().
// ConfigValues may be satellite address URLs with a node id.  Alternatively,
// ConfigValues may be local or HTTP(S) files which contain one satellite address per line,
// the same format as https://tardigrade.io/trusted-satellites.  HasNodeList indicates
// if any configValue is a node address list, indicating it should be polled for updates.
func LoadSatelliteIDs(ctx context.Context, configValues []string) (satMap map[storj.NodeID]struct{}, hasNodeList bool, err error) {
	satMap = make(map[storj.NodeID]struct{})
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
			bodyBytes, err := ioutil.ReadFile(c)
			if err != nil {
				return satMap, hasNodeList, ErrAllowedSatelliteList.Wrap(err)
			}
			err = readSatelliteList(bodyBytes, satMap)
			if err != nil {
				return satMap, hasNodeList, ErrAllowedSatelliteList.Wrap(err)
			}
		} else if nodeID, err := ParseSatelliteID(c); err == nil {
			satMap[nodeID] = struct{}{}
		} else {
			return satMap, hasNodeList, ErrAllowedSatelliteList.New("unknown config value '%s'", c)
		}
	}
	return satMap, hasNodeList, nil
}

// readSatelliteList populates a map from a newline separated list of Satellite
// addresses.  Empty lines or lines starting with '#' (comments) are ignored.
func readSatelliteList(input []byte, satellites map[storj.NodeID]struct{}) (err error) {
	for _, line := range bytes.Split(input, []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		nodeID, err := ParseSatelliteID(string(line))
		if err != nil {
			return err // already wrapped
		}
		satellites[nodeID] = struct{}{}
	}
	return nil
}

func getHTTPList(ctx context.Context, url string) ([]byte, error) {
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
	bodyBytes, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, ErrAllowedSatelliteList.Wrap(err)
	}
	return bodyBytes, nil
}

// ParseSatelliteID parses a Satellite identifier and returns the ID.
func ParseSatelliteID(s string) (id storj.NodeID, err error) {
	url, err := storj.ParseNodeURL(s)
	if err != nil {
		return storj.NodeID{}, ErrAllowedSatelliteList.Wrap(err)
	}

	if url.ID.IsZero() {
		nodeID, found := rpc.KnownNodeID(url.Address)
		if !found {
			return storj.NodeID{}, ErrAllowedSatelliteList.New("unknown satellite %q", s)
		}
		url.ID = nodeID
	}

	return url.ID, nil
}
