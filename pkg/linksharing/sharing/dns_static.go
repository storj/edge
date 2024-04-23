// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package sharing

import (
	"bytes"
	"context"
	"net/url"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/zeebo/errs"
)

// StaticDNSClient provides static responses to dns queries.
type StaticDNSClient struct {
	txt   map[string]*TXTRecordSet
	cname map[string][]string
}

// ParseStaticDNSClientFromZoneFile parses zone file for txt records.
func ParseStaticDNSClientFromZoneFile(data []byte) (*StaticDNSClient, error) {
	client := &StaticDNSClient{
		txt:   map[string]*TXTRecordSet{},
		cname: map[string][]string{},
	}

	zp := dns.NewZoneParser(bytes.NewReader(data), "", "")
	for {
		rr, ok := zp.Next()
		if !ok {
			break
		}

		switch rec := rr.(type) {
		case *dns.TXT:
			domain := rec.Hdr.Name
			ttl := time.Duration(rec.Hdr.Ttl) * time.Second

			set, ok := client.txt[domain]
			if !ok {
				set = NewTXTRecordSet()
				client.txt[domain] = set
			}

			for _, txt := range rec.Txt {
				set.Add(txt, ttl)
			}
		case *dns.CNAME:
			domain := rec.Hdr.Name
			client.cname[domain] = append(client.cname[domain], rec.Target)
		}
	}
	if err := zp.Err(); err != nil {
		return nil, errDNS.Wrap(err)
	}

	for _, set := range client.txt {
		set.Finalize()
	}

	return client, nil
}

// LookupTXTRecordSet fetches record set from the specified host.
func (cli *StaticDNSClient) LookupTXTRecordSet(ctx context.Context, host string) (_ *TXTRecordSet, err error) {
	defer mon.Task()(&ctx)(&err)

	if !strings.HasSuffix(host, ".") {
		host += "."
	}

	set, ok := cli.txt[host]
	if !ok {
		return nil, errDNS.New("not found")
	}

	return set, nil
}

// ValidateCNAME checks host has a CNAME record with a value of one of the public URL bases.
func (cli *StaticDNSClient) ValidateCNAME(ctx context.Context, host string, bases []*url.URL) (err error) {
	defer mon.Task()(&ctx)(&err)

	if !strings.HasSuffix(host, ".") {
		host += "."
	}

	for _, url := range bases {
		for _, target := range cli.cname[host] {
			if target == url.Host || target == url.Host+"." {
				return nil
			}
		}
	}

	return errs.New("domain %q does not contain a CNAME with any public host", host)
}
