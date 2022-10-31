// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package sharing

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// TXTRecordSet is somewhat like a url.Values wrapper type for key/value
// pairs defined across multiple TXT records.
//
// TXT records can be defined in a number of ways:
//   - TXT sub.domain.tld "a value"
//   - TXT sub.domain.tld "field:value"
//   - TXT sub.domain.tld "another-field:value" "another-field-again:value"
//
// This data structure ignores the first type (TXT records without a colon)
// but presents all of the key/value representations in a uniform manner.
type TXTRecordSet struct {
	vals   map[string][]string
	minTTL time.Duration
}

// NewTXTRecordSet constructs an empty TXTRecordSet.
func NewTXTRecordSet() *TXTRecordSet {
	return &TXTRecordSet{
		vals:   map[string][]string{},
		minTTL: 24 * time.Hour,
	}
}

// Add adds a new TXT record to the record set.
func (set *TXTRecordSet) Add(txt string, ttl time.Duration) {
	if set.minTTL > ttl {
		set.minTTL = ttl
	}
	fields := strings.SplitN(txt, ":", 2)
	if len(fields) != 2 {
		return
	}
	key := strings.ToLower(fields[0])
	key = strings.ReplaceAll(key, "_", "-")
	set.vals[key] = append(set.vals[key], fields[1])
}

// Finalize makes all values in the TXTRecordSet deterministic, regardless
// of TXT record response order, by sorting the values.
func (set *TXTRecordSet) Finalize() {
	for key := range set.vals {
		sort.Strings(set.vals[key])
	}
}

// Lookup will return the first value named by a given field in a TXT record
// set. Because TXT records have length limitations, if Lookup doesn't find
// the field directly, it will try to concatenate fields with ordered number
// suffixes. For instance:
//   - TXT sub.domain.tld "field-3:c"
//   - TXT sub.domain.tld "field-1:a" "field-2:b"
//
// will be concatenated as when "field" is looked up as "abc".
func (set *TXTRecordSet) Lookup(field string) (value string) {
	if len(set.vals[field]) > 0 {
		return set.vals[field][0]
	}

	for i := 1; true; i++ {
		subfield := fmt.Sprintf("%s-%d", field, i)
		if len(set.vals[subfield]) > 0 {
			value += set.vals[subfield][0]
		} else {
			break
		}
	}

	return value
}

// TTL returns the minimum TTL seen in the reecord set.
func (set *TXTRecordSet) TTL() time.Duration { return set.minTTL }
