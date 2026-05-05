// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

// Package httpcoding implements helpers for negotiating HTTP content
// codings per RFC 9110 Section 12.5.3.
package httpcoding

import (
	"math"
	"net/http"
	"strconv"
	"strings"
)

// Common content coding tokens.
const (
	Identity = "identity"
	Gzip     = "gzip"
)

var spaceReplacer = strings.NewReplacer(" ", "", "\t", "")

// IsAcceptable reports whether coding is acceptable per the request's
// Accept-Encoding header in accordance with RFC 9110 Section 12.5.3.
//
// It panics if coding is the wildcard token ("*").
func IsAcceptable(coding string, header http.Header) bool {
	coding = strings.ToLower(coding)
	if coding == "*" {
		panic("'*' is a reserved content coding token")
	}
	if _, ok := header["Accept-Encoding"]; !ok {
		return true
	}
	codingWeights := ParseAcceptEncoding(header)
	if len(codingWeights) == 0 {
		return coding == Identity
	}
	if weight, hasCoding := codingWeights[coding]; hasCoding {
		return weight > 0
	}
	if wildcardWeight, hasWildcard := codingWeights["*"]; hasWildcard {
		return wildcardWeight > 0
	}
	// Identity is implicitly acceptable when not explicitly refused.
	return coding == Identity
}

// ParseAcceptEncoding parses the Accept-Encoding header into a coding
// -> q-weight map in accordance with RFC 9110 Section 12.5.3.
func ParseAcceptEncoding(header http.Header) map[string]float64 {
	codingWeights := make(map[string]float64)
	value := strings.ToLower(spaceReplacer.Replace(header.Get("Accept-Encoding")))
	for _, codingWeight := range strings.Split(value, ",") {
		parts := strings.Split(codingWeight, ";")
		if parts[0] == "" {
			continue
		}
		weight := 1.0
		if len(parts) > 1 && strings.HasPrefix(parts[1], "q=") {
			if q, err := strconv.ParseFloat(parts[1][2:], 64); err == nil {
				weight = math.Min(math.Max(0, q), 1)
			}
		}
		codingWeights[parts[0]] = weight
	}
	return codingWeights
}
