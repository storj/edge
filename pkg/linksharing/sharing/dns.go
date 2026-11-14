// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package sharing

import (
	"context"
	"net"
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

// resolvConfPath is where nameservers are read from when no DNS servers
// are configured.
const resolvConfPath = "/etc/resolv.conf"

// DNSClient is a wrapper utility around github.com/miekg/dns to make it
// a bit more palatable and client user friendly.
type DNSClient struct {
	c       *dns.Client
	servers []string

	static *StaticDNSClient
}

// NewDNSClient creates a DNS Client for dnsServers, a comma-separated list
// of host:port addresses tried in order until one answers. If dnsServers
// is empty, the nameservers in /etc/resolv.conf are used, which isn't
// supported on Windows. "file:<path>" serves records from a zone file.
// The DNS servers must speak TCP.
func NewDNSClient(dnsServers string) (*DNSClient, error) {
	if after, ok := strings.CutPrefix(dnsServers, "file:"); ok {
		path := after

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

	var servers []string
	var err error
	if dnsServers == "" {
		servers, err = resolvConfServers(resolvConfPath)
	} else {
		servers, err = parseDNSServers(dnsServers)
	}
	if err != nil {
		return nil, err
	}

	return &DNSClient{
		c:       &dns.Client{Net: "tcp"},
		servers: servers,
	}, nil
}

func parseDNSServers(list string) ([]string, error) {
	var servers []string
	for server := range strings.SplitSeq(list, ",") {
		server = strings.TrimSpace(server)
		if _, _, err := net.SplitHostPort(server); err != nil {
			return nil, errDNS.New("invalid dns server %q: %w", server, err)
		}
		servers = append(servers, server)
	}
	return servers, nil
}

func resolvConfServers(path string) ([]string, error) {
	cfg, err := dns.ClientConfigFromFile(path)
	if err != nil {
		return nil, errDNS.New("unable to read nameservers (set a dns server explicitly if %q isn't available): %w", path, err)
	}
	if len(cfg.Servers) == 0 {
		return nil, errDNS.New("no nameservers in %q", path)
	}

	servers := make([]string, 0, len(cfg.Servers))
	for _, server := range cfg.Servers {
		servers = append(servers, net.JoinHostPort(server, cfg.Port))
	}
	return servers, nil
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
//
// Servers are tried in order, moving on when one is unreachable or can't
// answer (e.g. SERVFAIL). NXDOMAIN is an answer, so it isn't retried.
func (cli *DNSClient) lookup(ctx context.Context, host string, recordType uint16) (_ *dns.Msg, err error) {
	defer mon.Task()(&ctx)(&err)

	var m dns.Msg
	m.SetQuestion(dns.Fqdn(host), recordType)

	var group errs.Group
	for _, server := range cli.servers {
		r, _, err := cli.c.ExchangeContext(ctx, &m, server)
		if err == nil && r.Rcode != dns.RcodeSuccess && r.Rcode != dns.RcodeNameError {
			err = errs.New("%s", dns.RcodeToString[r.Rcode])
		}
		if err == nil {
			return r, nil
		}
		group.Add(errs.New("%s: %w", server, err))
		if ctx.Err() != nil {
			break
		}
	}
	return nil, errDNS.Wrap(group.Err())
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
