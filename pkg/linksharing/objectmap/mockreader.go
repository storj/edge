// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package objectmap

import (
	"errors"
	"net"
)

// ensures that MockReader implements Reader.
var _ Reader = (*MockReader)(nil)

// MockReader is a mock implementation of maxmind database reader interface.
type MockReader struct{}

// Lookup retrieves the database record for ip and stores it in the value
// pointed to by result.
func (mr *MockReader) Lookup(ip net.IP, result interface{}) error {
	// Valid geolocation case
	if ip.Equal(net.IPv4(172, 146, 10, 1)) {
		result.(*IPInfo).Location = mockIPInfo(-19.456, 20.123).Location
		return nil
	}
	// Location not found
	if ip.Equal(net.IPv4(1, 1, 1, 1)) {
		return errors.New("not found")
	}
	return nil
}

// Close closes underlying connection.
func (mr *MockReader) Close() error {
	return nil
}

func mockIPInfo(latitude, longitude float64) *IPInfo {
	return &IPInfo{
		Location: struct {
			Latitude  float64 `maxminddb:"latitude"`
			Longitude float64 `maxminddb:"longitude"`
		}{
			Latitude:  latitude,
			Longitude: longitude,
		},
	}
}
