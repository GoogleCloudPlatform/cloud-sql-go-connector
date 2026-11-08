// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cloudsqlconn

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"slices"
	"testing"
	"time"

	"cloud.google.com/go/cloudsqlconn/internal/cloudsql"
	"cloud.google.com/go/cloudsqlconn/internal/mock"
)

// unwrapTLSConn extracts the underlying *tls.Conn from a net.Conn returned by
// Dialer.Dial so tests can inspect the negotiated tls.ConnectionState.
func unwrapTLSConn(t *testing.T, conn net.Conn) *tls.Conn {
	t.Helper()
	ic, ok := conn.(*instrumentedConn)
	if !ok {
		t.Fatalf("expected *instrumentedConn, got %T", conn)
	}
	inner := ic.Conn
	if mdxConn, isMDX := inner.(*cloudsql.MDXConn); isMDX {
		inner = mdxConn.Conn
	}
	tlsConn, ok := inner.(*tls.Conn)
	if !ok {
		t.Fatalf("expected underlying *tls.Conn, got %T", inner)
	}
	return tlsConn
}

// assertTLSHandshakeAndExchange dials the mock instance, exchanges application
// data end to end, and verifies both the raw ClientHello supported_groups wire
// list (wantClientMLKEM) and that both client and mock server negotiated TLS
// 1.3 with wantCurve.
func assertTLSHandshakeAndExchange(
	t *testing.T,
	d *Dialer,
	inst mock.FakeCSQLInstance,
	clientCurves <-chan []tls.CurveID,
	serverStates <-chan tls.ConnectionState,
	wantClientMLKEM bool,
	wantCurve tls.CurveID,
	dialOpts ...DialOption,
) {
	t.Helper()
	conn, err := d.Dial(context.Background(), inst.String(), dialOpts...)
	if err != nil {
		t.Fatalf("expected Dial to succeed, got error: %v", err)
	}
	defer func() { _ = conn.Close() }()

	clientState := unwrapTLSConn(t, conn).ConnectionState()
	if !clientState.HandshakeComplete {
		t.Fatal("expected client TLS handshake to be complete")
	}
	if clientState.Version != tls.VersionTLS13 {
		t.Fatalf("client TLS version: want = 0x%04x (TLS 1.3), got = 0x%04x", tls.VersionTLS13, clientState.Version)
	}
	if clientState.CurveID != wantCurve {
		t.Fatalf("client negotiated CurveID: want = %v (0x%04x), got = %v (0x%04x)",
			wantCurve, uint16(wantCurve), clientState.CurveID, uint16(clientState.CurveID))
	}

	if _, err := conn.Write([]byte("hello world")); err != nil {
		t.Fatalf("expected Write to succeed, got error: %v", err)
	}
	data, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("expected ReadAll to succeed, got error: %v", err)
	}
	const wantPayload = "my-instance"
	if string(data) != wantPayload {
		t.Fatalf("unexpected response payload: want = %q, got = %q", wantPayload, string(data))
	}

	select {
	case gotCurves := <-clientCurves:
		if gotHasMLKEM := slices.Contains(gotCurves, tls.X25519MLKEM768); gotHasMLKEM != wantClientMLKEM {
			t.Fatalf("ClientHello SupportedCurves = %v: contains X25519MLKEM768 (0x%04x) = %v, want %v",
				gotCurves, uint16(tls.X25519MLKEM768), gotHasMLKEM, wantClientMLKEM)
		}
		if !wantClientMLKEM {
			for _, pqGroup := range []tls.CurveID{tls.SecP256r1MLKEM768, tls.SecP384r1MLKEM1024} {
				if slices.Contains(gotCurves, pqGroup) {
					t.Fatalf("ClientHello SupportedCurves = %v: unexpected hybrid group %v (0x%04x) when ML-KEM is disabled",
						gotCurves, pqGroup, uint16(pqGroup))
				}
			}
		}
		if !slices.Contains(gotCurves, tls.X25519) {
			t.Fatalf("ClientHello SupportedCurves = %v: expected classical X25519 fallback curve", gotCurves)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for server ClientHello SupportedCurves")
	}

	select {
	case serverState := <-serverStates:
		if !serverState.HandshakeComplete {
			t.Fatal("expected server TLS handshake to be complete")
		}
		if serverState.Version != tls.VersionTLS13 {
			t.Fatalf("server TLS version: want = 0x%04x (TLS 1.3), got = 0x%04x", tls.VersionTLS13, serverState.Version)
		}
		if serverState.CurveID != wantCurve {
			t.Fatalf("server negotiated CurveID: want = %v (0x%04x), got = %v (0x%04x)",
				wantCurve, uint16(wantCurve), serverState.CurveID, uint16(serverState.CurveID))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for server TLS ConnectionState")
	}
}

func TestDialerPQCDefaultHandshake(t *testing.T) {
	if uint16(tls.X25519MLKEM768) != 0x11ec {
		t.Fatalf("unexpected IANA code point for tls.X25519MLKEM768: got 0x%04x, want 0x11ec", uint16(tls.X25519MLKEM768))
	}

	tcs := []struct {
		desc     string
		instOpts []mock.FakeCSQLInstanceOption
		dialOpts []DialOption
	}{
		{
			desc: "default connection negotiates X25519MLKEM768",
		},
		{
			desc: "metadata exchange connection negotiates X25519MLKEM768",
			dialOpts: []DialOption{
				WithMdxClientProtocolType(cloudsql.ClientProtocolTCP),
			},
		},
		{
			desc: "CAS instance connection negotiates X25519MLKEM768",
			instOpts: []mock.FakeCSQLInstanceOption{
				mock.WithDNS("db.example.com"),
				mock.WithServerCAMode("GOOGLE_MANAGED_CAS_CA"),
			},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.desc, func(t *testing.T) {
			inst := mock.NewFakeCSQLInstance(
				"my-project", "my-region", "my-instance",
				tc.instOpts...,
			)
			clientCurves := make(chan []tls.CurveID, 1)
			serverStates := make(chan tls.ConnectionState, 1)
			d := setupDialer(t, setupConfig{
				testInstance: inst,
				reqs: []*mock.Request{
					mock.InstanceGetSuccess(inst, 1),
					mock.CreateEphemeralSuccess(inst, 1),
				},
				serverProxyOptions: []mock.ServerProxyOption{
					mock.WithServerClientHelloHook(func(chi *tls.ClientHelloInfo) {
						select {
						case clientCurves <- slices.Clone(chi.SupportedCurves):
						default:
						}
					}),
					mock.WithServerConnectionStateHook(func(st tls.ConnectionState) {
						select {
						case serverStates <- st:
						default:
						}
					}),
				},
			})
			t.Cleanup(func() { _ = d.Close() })

			assertTLSHandshakeAndExchange(t, d, inst, clientCurves, serverStates, true, tls.X25519MLKEM768, tc.dialOpts...)
		})
	}
}

func TestDialerPQCClassicalServerFallback(t *testing.T) {
	tcs := []struct {
		desc         string
		serverCurves []tls.CurveID
		wantCurve    tls.CurveID
	}{
		{
			desc:         "falls back to X25519 when server supports classical curves only",
			serverCurves: []tls.CurveID{tls.X25519, tls.CurveP256},
			wantCurve:    tls.X25519,
		},
		{
			desc:         "falls back to CurveP256 via HelloRetryRequest when server supports P-256 only",
			serverCurves: []tls.CurveID{tls.CurveP256},
			wantCurve:    tls.CurveP256,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.desc, func(t *testing.T) {
			inst := mock.NewFakeCSQLInstance(
				"my-project", "my-region", "my-instance",
			)
			clientCurves := make(chan []tls.CurveID, 1)
			serverStates := make(chan tls.ConnectionState, 1)
			d := setupDialer(t, setupConfig{
				testInstance: inst,
				reqs: []*mock.Request{
					mock.InstanceGetSuccess(inst, 1),
					mock.CreateEphemeralSuccess(inst, 1),
				},
				serverProxyOptions: []mock.ServerProxyOption{
					mock.WithServerCurvePreferences(tc.serverCurves...),
					mock.WithServerClientHelloHook(func(chi *tls.ClientHelloInfo) {
						select {
						case clientCurves <- slices.Clone(chi.SupportedCurves):
						default:
						}
					}),
					mock.WithServerConnectionStateHook(func(st tls.ConnectionState) {
						select {
						case serverStates <- st:
						default:
						}
					}),
				},
			})
			t.Cleanup(func() { _ = d.Close() })

			assertTLSHandshakeAndExchange(t, d, inst, clientCurves, serverStates, true, tc.wantCurve)
		})
	}
}

func TestDialerPQCOptOutWithGODEBUG(t *testing.T) {
	// Note: In Go 1.26+, crypto/tls filters Config.CurvePreferences against
	// defaultCurvePreferences(), so a process-wide GODEBUG=tlsmlkem=0 strips
	// ML-KEM groups from an in-process tls.Server as well as the client.
	// To verify client opt-out non-vacuously, assertTLSHandshakeAndExchange
	// inspects the raw ClientHelloInfo.SupportedCurves wire list captured via
	// GetConfigForClient before server-side curve filtering, alongside
	// verifying classical X25519 handshake completion.
	serverCurves := []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256}

	t.Run("omits ML-KEM groups and negotiates X25519 when GODEBUG=tlsmlkem=0", func(t *testing.T) {
		t.Setenv("GODEBUG", "tlsmlkem=0")

		inst := mock.NewFakeCSQLInstance(
			"my-project", "my-region", "my-instance",
		)
		clientCurves := make(chan []tls.CurveID, 1)
		serverStates := make(chan tls.ConnectionState, 1)
		d := setupDialer(t, setupConfig{
			testInstance: inst,
			reqs: []*mock.Request{
				mock.InstanceGetSuccess(inst, 1),
				mock.CreateEphemeralSuccess(inst, 1),
			},
			serverProxyOptions: []mock.ServerProxyOption{
				mock.WithServerCurvePreferences(serverCurves...),
				mock.WithServerClientHelloHook(func(chi *tls.ClientHelloInfo) {
					select {
					case clientCurves <- slices.Clone(chi.SupportedCurves):
					default:
					}
				}),
				mock.WithServerConnectionStateHook(func(st tls.ConnectionState) {
					select {
					case serverStates <- st:
					default:
					}
				}),
			},
		})
		t.Cleanup(func() { _ = d.Close() })

		assertTLSHandshakeAndExchange(t, d, inst, clientCurves, serverStates, false, tls.X25519)
	})

	t.Run("advertises and negotiates X25519MLKEM768 when GODEBUG=tlsmlkem=1", func(t *testing.T) {
		t.Setenv("GODEBUG", "tlsmlkem=1")

		inst := mock.NewFakeCSQLInstance(
			"my-project", "my-region", "my-instance",
		)
		clientCurves := make(chan []tls.CurveID, 1)
		serverStates := make(chan tls.ConnectionState, 1)
		d := setupDialer(t, setupConfig{
			testInstance: inst,
			reqs: []*mock.Request{
				mock.InstanceGetSuccess(inst, 1),
				mock.CreateEphemeralSuccess(inst, 1),
			},
			serverProxyOptions: []mock.ServerProxyOption{
				mock.WithServerCurvePreferences(serverCurves...),
				mock.WithServerClientHelloHook(func(chi *tls.ClientHelloInfo) {
					select {
					case clientCurves <- slices.Clone(chi.SupportedCurves):
					default:
					}
				}),
				mock.WithServerConnectionStateHook(func(st tls.ConnectionState) {
					select {
					case serverStates <- st:
					default:
					}
				}),
			},
		})
		t.Cleanup(func() { _ = d.Close() })

		assertTLSHandshakeAndExchange(t, d, inst, clientCurves, serverStates, true, tls.X25519MLKEM768)
	})
}
