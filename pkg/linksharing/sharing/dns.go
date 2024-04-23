// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package sharing

import (
	"context"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/zeebo/errs"
)

var (
	errDNS = errs.Class("dns error")
)

// DNSClient is a wrapper utility around github.com/miekg/dns to make it
// a bit more palatable and client user friendly.
type DNSClient struct {
	c         *dns.Client
	dnsServer string

	static *StaticDNSClient
}

// NewDNSClient creates a DNS Client that uses the given
// dnsServerAddr. Currently requires that the DNS Server speaks TCP.
func NewDNSClient(dnsServerAddr string) (*DNSClient, error) {
	if strings.HasPrefix(dnsServerAddr, "file:") {
		path := strings.TrimPrefix(dnsServerAddr, "file:")

		data, err := os.ReadFile(path)
		if err != nil {
			return nil, errDNS.New("unable to read %q: %w", path, err)
		}

		static, err := ParseStaticDNSClientFromZoneFile(data)
		if err != nil {
			return nil, errDNS.New("unable to parse %q: %w", path, err)
		}

		return &DNSClient{
			static: static,
		}, nil
	}

	return &DNSClient{
		c:         &dns.Client{Net: "tcp"},
		dnsServer: dnsServerAddr,
	}, nil
}

// LookupTXTRecordSet fetches record set from the specified host.
func (cli *DNSClient) LookupTXTRecordSet(ctx context.Context, host string) (_ *TXTRecordSet, err error) {
	defer mon.Task()(&ctx)(&err)

	if cli.static != nil {
		return cli.static.LookupTXTRecordSet(ctx, host)
	}

	r, err := cli.lookup(ctx, host, dns.TypeTXT)
	if err != nil {
		return nil, errDNS.Wrap(err)
	}
	return ResponseToTXTRecordSet(r), nil
}

// ValidateCNAME checks name has a CNAME record with a value of one of the public URL bases.
func (cli *DNSClient) ValidateCNAME(ctx context.Context, name string, bases []*url.URL) (err error) {
	defer mon.Task()(&ctx)(&err)

	if cli.static != nil {
		return cli.static.ValidateCNAME(ctx, name, bases)
	}

	msg, err := cli.lookup(ctx, name, dns.TypeCNAME)
	if err != nil {
		return err
	}

	for _, url := range bases {
		for _, answer := range msg.Answer {
			rec, ok := answer.(*dns.CNAME)
			if !ok {
				continue
			}

			// rec.Target should always have a suffixed dot as it's an alias value
			// but we'll check both anyway.
			if rec.Target == url.Host || rec.Target == url.Host+"." {
				return nil
			}
		}
	}

	return errs.New("domain %q does not contain a CNAME with any public host", name)
}

// lookup is a helper method that never returns truncated DNS messages.
// The current implementation does this by doing all lookups over TCP.
func (cli *DNSClient) lookup(ctx context.Context, host string, recordType uint16) (_ *dns.Msg, err error) {
	defer mon.Task()(&ctx)(&err)
	m := dns.Msg{}
	m.SetQuestion(dns.Fqdn(host), recordType)
	r, _, err := cli.c.ExchangeContext(ctx, &m, cli.dnsServer)
	return r, errDNS.Wrap(err)
}

// ResponseToTXTRecordSet returns a TXTRecordSet from a dns Lookup response.
func ResponseToTXTRecordSet(resp *dns.Msg) *TXTRecordSet {
	set := NewTXTRecordSet()
	defer set.Finalize()
	for _, ans := range resp.Answer {
		rec, ok := ans.(*dns.TXT)
		if !ok {
			continue
		}
		ttl := time.Duration(rec.Hdr.Ttl) * time.Second
		for _, txt := range rec.Txt {
			set.Add(txt, ttl)
		}
	}
	return set
}
