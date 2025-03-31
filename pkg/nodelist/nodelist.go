// Copyright (C) 2023 Storj Labs, Inc.
// See LICENSE for copying information.

package nodelist

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

// Error is an error class of node list errors.
var Error = errs.Class("node list")

// Resolve takes a list of configuration paths and returns a list of deduplicated
// NodeURLs.
//
// configValues can be one or more of the following:
//   - A URL that responds with node IDs newline separated.
//     e.g. https://www.storj.io/dcs-satellites
//   - A local file path containing node IDs newline separated.
//     e.g. /path/to/my/satellites.txt
//   - Individual satellite node URLs.
//     e.g. 12EayRS2V1kEsWESU9QMRseFhdxYxKicsiFmxrsLZHeLUtdps3S@us1.storj.io:7777
//
// HasNodeList indicates if any configValue is a node address list, indicating
// it should be polled for updates.
func Resolve(ctx context.Context, configValues []string) (satMap map[storj.NodeURL]struct{}, hasNodeList bool, err error) {
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
			err = readNodeList(fileContent, satMap)
			if err != nil {
				return satMap, hasNodeList, Error.Wrap(err)
			}
		} else if _, err := os.Stat(c); err == nil {
			hasNodeList = true
			bodyBytes, err := os.ReadFile(c)
			if err != nil {
				return satMap, hasNodeList, Error.Wrap(err)
			}
			err = readNodeList(bodyBytes, satMap)
			if err != nil {
				return satMap, hasNodeList, Error.Wrap(err)
			}
		} else if nodeURL, err := ParseNodeURL(c); err == nil {
			satMap[nodeURL] = struct{}{}
		} else {
			return satMap, hasNodeList, Error.New("unknown config value '%s'", c)
		}
	}
	return satMap, hasNodeList, nil
}

// readList populates a map from a newline separated list of node addresses.
// Empty lines or lines starting with '#' (comments) are ignored.
func readNodeList(input []byte, satellites map[storj.NodeURL]struct{}) (err error) {
	for _, line := range bytes.Split(input, []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		nodeURL, err := ParseNodeURL(string(line))
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, Error.Wrap(err)
	}
	res, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return nil, Error.Wrap(err)
	}
	defer func() { err = errs.Combine(err, Error.Wrap(res.Body.Close())) }()

	if res.StatusCode != http.StatusOK {
		return nil, Error.New("HTTP failed with HTTP status %d", res.StatusCode)
	}
	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, Error.Wrap(err)
	}
	return bodyBytes, nil
}

// ParseNodeURL parses a node address and returns the URL.
func ParseNodeURL(s string) (id storj.NodeURL, err error) {
	url, err := storj.ParseNodeURL(s)
	if err != nil {
		return storj.NodeURL{}, Error.Wrap(err)
	}

	if url.ID.IsZero() {
		nodeID, found := rpc.KnownNodeID(url.Address)
		if !found {
			return storj.NodeURL{}, Error.New("unknown node %q", s)
		}
		url.ID = nodeID
	}

	return url, nil
}
