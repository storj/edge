// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package auth

import (
	"context"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/zeebo/errs"

	"storj.io/common/storj"
)

// ErrAllowedSatelliteList is an error class for allowed satellite list errors.
var ErrAllowedSatelliteList = errs.Class("allowed satellite list")

// LoadSatelliteAddresses takes a list of configuration paths and returns a list of
// satellites addresses suitable for calling ("*Database).SetAllowedSatellites().
// ConfigValues may be satellite address URLs with or without a node id.  Alternatively,
// ConfigValues may be local or HTTP files which contain one satellite address per line,
// the same format as https://tardigrade.io/trusted-satellites.  HasAddressList indicates
// if any configValue is a node address list, indicating it should be polled for updates.
func LoadSatelliteAddresses(ctx context.Context, configValues []string) (satMap map[string]struct{}, hasAddressList bool, err error) {
	satMap = make(map[string]struct{})
	for _, c := range configValues {
		c = strings.TrimSpace(c)
		if strings.HasPrefix(c, "http") {
			hasAddressList = true
			fileContent, err := getHTTPList(ctx, c)
			if err != nil {
				return satMap, hasAddressList, err
			}
			err = readSatelliteList(fileContent, satMap)
			if err != nil {
				return satMap, hasAddressList, ErrAllowedSatelliteList.Wrap(err)
			}
		} else if _, err := os.Stat(c); err == nil {
			hasAddressList = true
			bodyBytes, err := ioutil.ReadFile(c)
			if err != nil {
				return satMap, hasAddressList, ErrAllowedSatelliteList.Wrap(err)
			}
			err = readSatelliteList(string(bodyBytes), satMap)
			if err != nil {
				return satMap, hasAddressList, ErrAllowedSatelliteList.Wrap(err)
			}
		} else if address, err := parseSatelliteAddress(c); err == nil {
			satMap[address] = struct{}{}
		} else {
			return satMap, hasAddressList, ErrAllowedSatelliteList.New("unknown config value '%s'", c)
		}
	}
	return satMap, hasAddressList, nil
}

// readSatelliteList populates a map from a newline separated list of Satellite
// addresses.  Empty lines or lines starting with '#' (comments) are ignored.
func readSatelliteList(input string, satellites map[string]struct{}) (err error) {
	for _, line := range strings.Split(input, "\n") {
		line = strings.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		address, err := parseSatelliteAddress(line)
		if err != nil {
			return err // already wrapped
		}
		satellites[address] = struct{}{}
	}
	return nil
}

func getHTTPList(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", ErrAllowedSatelliteList.Wrap(err)
	}
	res, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return "", ErrAllowedSatelliteList.Wrap(err)
	}
	defer func() { err = errs.Combine(err, ErrAllowedSatelliteList.Wrap(res.Body.Close())) }()

	if res.StatusCode != 200 {
		return "", ErrAllowedSatelliteList.New("HTTP failed with HTTP status %d", res.StatusCode)
	}
	bodyBytes, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", ErrAllowedSatelliteList.Wrap(err)
	}
	return string(bodyBytes), nil
}

// parseSatelliteAddress parses a Satellite identifier and returns the address.
func parseSatelliteAddress(s string) (address string, err error) {
	url, err := storj.ParseNodeURL(s)
	if err != nil {
		return "", ErrAllowedSatelliteList.Wrap(err)
	}
	if url.Address == "" {
		return "", ErrAllowedSatelliteList.New("must specify the host:port")
	}
	host, port, err := net.SplitHostPort(url.Address)
	if err != nil {
		return "", ErrAllowedSatelliteList.New("must specify the port")
	}
	return host + ":" + port, nil
}
