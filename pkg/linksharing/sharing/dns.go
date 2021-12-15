// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package sharing

import (
	"context"
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
}

// NewDNSClient creates a DNS Client that uses the given
// dnsServerAddr. Currently requires that the DNS Server speaks TCP.
func NewDNSClient(dnsServerAddr string) (*DNSClient, error) {
	return &DNSClient{
		c:         &dns.Client{Net: "tcp"},
		dnsServer: dnsServerAddr,
	}, nil
}

// Lookup is a helper method that never returns truncated DNS messages.
// The current implementation does this by doing all lookups over TCP.
func (cli *DNSClient) Lookup(ctx context.Context, host string, recordType uint16) (_ *dns.Msg, err error) {
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
