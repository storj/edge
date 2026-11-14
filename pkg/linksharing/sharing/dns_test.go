// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package sharing

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"

	"storj.io/common/testcontext"
)

func TestParseDNSServers(t *testing.T) {
	servers, err := parseDNSServers("8.8.8.8:53")
	require.NoError(t, err)
	require.Equal(t, []string{"8.8.8.8:53"}, servers)

	servers, err = parseDNSServers("8.8.8.8:53, 1.1.1.1:53,[2606:4700:4700::1111]:53")
	require.NoError(t, err)
	require.Equal(t, []string{"8.8.8.8:53", "1.1.1.1:53", "[2606:4700:4700::1111]:53"}, servers)

	for _, invalid := range []string{"8.8.8.8", "8.8.8.8:53,", "8.8.8.8:53,,1.1.1.1:53", " "} {
		_, err := parseDNSServers(invalid)
		require.Error(t, err, invalid)
	}
}

func TestResolvConfServers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolv.conf")
	require.NoError(t, os.WriteFile(path, []byte("search example.com\nnameserver 10.0.0.1\nnameserver fd00::1\n"), 0o644))

	servers, err := resolvConfServers(path)
	require.NoError(t, err)
	require.Equal(t, []string{"10.0.0.1:53", "[fd00::1]:53"}, servers)

	require.NoError(t, os.WriteFile(path, []byte("search example.com\n"), 0o644))
	_, err = resolvConfServers(path)
	require.Error(t, err)

	_, err = resolvConfServers(filepath.Join(t.TempDir(), "missing"))
	require.Error(t, err)
}

func TestDNSClientFallback(t *testing.T) {
	ctx := testcontext.New(t)

	// A closed listener's address refuses connections.
	unreachable, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	require.NoError(t, unreachable.Close())

	servfail := startDNSServer(ctx, t, func(w dns.ResponseWriter, r *dns.Msg) {
		var m dns.Msg
		m.SetRcode(r, dns.RcodeServerFailure)
		_ = w.WriteMsg(&m)
	})

	working := startDNSServer(ctx, t, func(w dns.ResponseWriter, r *dns.Msg) {
		var m dns.Msg
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300},
			Txt: []string{"storj-root:files"},
		})
		_ = w.WriteMsg(&m)
	})

	client, err := NewDNSClient(unreachable.Addr().String() + "," + servfail + "," + working)
	require.NoError(t, err)

	set, err := client.LookupTXTRecordSet(ctx, "txt-example.com")
	require.NoError(t, err)
	require.Equal(t, "files", set.Lookup("storj-root"))

	client, err = NewDNSClient(unreachable.Addr().String() + "," + servfail)
	require.NoError(t, err)

	_, err = client.LookupTXTRecordSet(ctx, "txt-example.com")
	require.ErrorContains(t, err, unreachable.Addr().String())
	require.ErrorContains(t, err, "SERVFAIL")
}

func startDNSServer(ctx *testcontext.Context, t *testing.T, handler dns.HandlerFunc) string {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	server := &dns.Server{Listener: listener, Handler: handler}
	ctx.Go(server.ActivateAndServe)
	t.Cleanup(func() { require.NoError(t, server.Shutdown()) })

	return listener.Addr().String()
}
