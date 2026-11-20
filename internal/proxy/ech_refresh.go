package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"cornelius/internal/config"
	"cornelius/internal/proxy/factory"
	"cornelius/internal/proxy/pool"
	"cornelius/internal/telemetry"
)

// ECH config refresh through the tunnel.
//
// The dialer's first ECH fetch goes out over direct DoH — at cold start
// there is no tunnel yet to fetch through. But once a tunnel is up, every
// refresh should ride inside it: the ISP then sees no DoH query at all,
// and the resolver sees the query coming from the Worker's egress
// instead of the user's address. A refresher loop keeps the factory's
// cache fresh through the tunnel, so the dialer almost never needs the
// direct path after bootstrap.
//
// Honest scope: cold start still uses direct DoH (or the pasted config
// in strict mode). If direct DoH is blocked at startup in non-strict
// mode, the first dials fall back to fragmentation without ECH, the pool
// warms, and the refresher fetches through the tunnel — later dials get
// ECH. In strict mode without a pasted config there is no tunnel to
// refresh through, so the pasted config remains the strict bootstrap.

// dohHost is the DoH resolver the tunnel stream is opened to.
// dns.google, not cloudflare-dns.com: Cloudflare Workers' connect()
// refuses outbound TCP to Cloudflare's own IP space, so a stream to
// cloudflare-dns.com is RST'd by the runtime before any bytes flow
// (the client sees io.EOF ~150-330 ms after opening the stream, every
// refresh tick). dns.google serves the same /dns-query endpoint and is
// not a Cloudflare address, so the Worker can actually dial it.
const dohHost = "dns.google"

// streamConn adapts a SMUX stream to a net.Conn so the factory's
// over-tunnel DoH exchange can run over it. A stream has no addresses
// and no deadlines, so the deadline methods are no-ops — and that is
// safe here only because the fetch is bounded twice over: the HTTP
// request carries a context timeout, and the transport aborts a
// cancelled request by closing the stream, which unblocks any pending
// Read; and the session's keepalive kills a silent session after 25s
// of no traffic. If this adapter is ever used for an exchange without
// a context timeout, the no-op deadlines become a real hang risk.
type streamConn struct {
	*smuxStream
}

type dummyAddr struct{}

func (dummyAddr) Network() string { return "smux" }
func (dummyAddr) String() string  { return "smux-stream" }

func (c *streamConn) LocalAddr() net.Addr              { return dummyAddr{} }
func (c *streamConn) RemoteAddr() net.Addr             { return dummyAddr{} }
func (c *streamConn) SetDeadline(time.Time) error      { return nil }
func (c *streamConn) SetReadDeadline(time.Time) error  { return nil }
func (c *streamConn) SetWriteDeadline(time.Time) error { return nil }

var _ net.Conn = (*streamConn)(nil)

// overConnTLSConfig is the TLS config for the DoH-over-tunnel exchange:
// the resolver's real name, verified against the system roots.
// Overridden by tests.
var overConnTLSConfig = &tls.Config{ServerName: dohHost, NextProtos: []string{"http/1.1"}}

// fetchECHThroughSession opens one stream to the DoH resolver on an
// existing tunnel session and fetches the ECH config for host through
// it. The session stays open; only the stream is closed.
func fetchECHThroughSession(ctx context.Context, sess *smuxSession, host string) ([]byte, time.Duration, error) {
	streamCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	st, err := sess.OpenStream(streamCtx, dohHost, 443)
	if err != nil {
		return nil, 0, fmt.Errorf("could not open a tunnel stream to %s: %w", dohHost, err)
	}
	defer st.Close()
	return factory.FetchECHConfigListOverConn(streamCtx, host, &streamConn{st}, overConnTLSConfig, dohHost)
}

// FetchECHConfigThroughConn fetches the ECH config for host through a
// tunnel connection: it opens a SMUX session over conn, fetches through
// one stream, then closes the session — which closes conn. The caller
// must treat conn as consumed, exactly like a SOCKS connection consumes
// an acquired pipe.
func FetchECHConfigThroughConn(ctx context.Context, conn net.Conn, host string) ([]byte, time.Duration, error) {
	sess := newSmuxSession(conn)
	defer sess.Close()
	return fetchECHThroughSession(ctx, sess, host)
}

// needsECHRefresh is the refresher's decision, kept small so it can be
// unit-tested: refresh only when ECH is on, the host is known, and the
// dialer has no fresh cached config.
func needsECHRefresh(echEnabled bool, host string) bool {
	return echEnabled && host != "" && !factory.ECHConfigFresh(host)
}

// refreshECHOnce tries a single through-tunnel refresh: it acquires one
// warm pipe, fetches the config through it, and stores the result in
// the factory cache. The pipe is consumed by the fetch, and the pool
// replenishes it. Any failure is an error for the caller to log — the
// direct DoH path inside the dialer remains the fallback.
func refreshECHOnce(ctx context.Context, warmPool *pool.WarmPool, host string) error {
	// One bound for the whole operation: acquire plus fetch. The fetch
	// has its own tighter inner timeouts (15s stream, 10s HTTP), but
	// the outer bound is what guarantees the attempt ends.
	opCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	conn, err := warmPool.Acquire(opCtx)
	if err != nil {
		return fmt.Errorf("no warm tunnel to refresh through: %w", err)
	}
	list, ttl, err := FetchECHConfigThroughConn(opCtx, conn, host)
	if err != nil {
		return err
	}
	factory.StoreECHConfig(host, list, ttl)
	return nil
}

// StartECHRefreshLoop keeps the ECH config fresh through the tunnel for
// as long as the daemon runs. It ticks once a minute and attempts a
// refresh only when the dialer's cache is stale, so in steady state it
// does nothing at all. The first attempt waits a few seconds after
// startup so the pool has a chance to warm. It never fails the daemon:
// a failed refresh is logged and retried on the next tick, and the
// dialer's direct DoH fetch covers the gap meanwhile.
func StartECHRefreshLoop(ctx context.Context, warmPool *pool.WarmPool, profile *config.CombatProfile) {
	sf := profile.Modules.StealthFactory
	if !sf.ECHEnabled || profile.WorkerHost == "" {
		return
	}
	host := profile.WorkerHost
	go func() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(10 * time.Second):
		}
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			if needsECHRefresh(true, host) {
				if err := refreshECHOnce(ctx, warmPool, host); err != nil {
					telemetry.Log.Warn("ECH refresh through the tunnel failed; direct DoH remains the fallback", "host", host, "err", err.Error())
				} else {
					name := ""
					if list, ok := factory.CachedECHConfig(host); ok {
						name, _ = factory.ECHPublicName(list)
					}
					telemetry.Log.Info("ECH config refreshed through the tunnel", "host", host, "public_name", name)
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}
