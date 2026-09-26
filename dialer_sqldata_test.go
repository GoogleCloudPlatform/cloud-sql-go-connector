// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cloudsqlconn

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"cloud.google.com/go/cloudsqlconn/errtype"
	"cloud.google.com/go/cloudsqlconn/instance"
	"cloud.google.com/go/cloudsqlconn/internal/mock"
	"cloud.google.com/go/cloudsqlconn/internal/sqldataclient"
	sqlpb "cloud.google.com/go/sql/apiv1beta4/sqlpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func startMockServer(t *testing.T, handler func(sqlpb.SqlDataService_StreamSqlDataServer) error) (string, func()) {
	lis, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer(
		grpc.MaxRecvMsgSize(100*1024*1024),
		grpc.MaxSendMsgSize(100*1024*1024),
	)
	fakeServer := &mock.FakeSQLDataServiceServer{
		OnStreamSQLData: handler,
	}
	sqlpb.RegisterSqlDataServiceServer(s, fakeServer)
	go func() {
		_ = s.Serve(lis)
	}()
	return lis.Addr().String(), func() { s.Stop() }
}

func TestDialerWithSqlData(t *testing.T) {
	handler := func(stream sqlpb.SqlDataService_StreamSqlDataServer) error {
		// Read initial connection settings
		req, err := stream.Recv()
		if err != nil {
			return err
		}
		if req.GetStartSession() == nil {
			return fmt.Errorf("expected StartSession, got %v", req)
		}
		// Echo loop
		for {
			req, err := stream.Recv()
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return err
			}

			data := req.GetData()
			if data != nil {
				// Echo back
				err := stream.Send(&sqlpb.StreamSqlDataResponse{
					Message: &sqlpb.StreamSqlDataResponse_Data{
						Data: &sqlpb.DataPacket{
							Data: data.GetData(),
						},
					},
				})
				if err != nil {
					return err
				}
			}
		}
	}

	addr, cleanup := startMockServer(t, handler)
	defer cleanup()

	// 3. Initialize Dialer
	ctx := context.Background()
	d, err := newTestDialer(ctx, addr, 45*time.Minute)
	if err != nil {
		t.Fatalf("NewDialer failed: %v", err)
	}
	defer d.Close()

	// 4. Connect
	conn, err := d.Dial(ctx, "proj:reg:inst", WithSQLData())
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer conn.Close()

	// 5. Send/Receive Data
	msg := []byte("hello world")
	_, err = conn.Write(msg)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	buf := make([]byte, len(msg))
	_, err = conn.Read(buf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	err = conn.Close()
	if err != nil {
		t.Fatalf("close failed: %v", err)
	}

	if string(buf) != string(msg) {
		t.Errorf("Got %q, want %q", string(buf), string(msg))
	}
}

func TestDialerWithSqlData_ConnectionFailure(t *testing.T) {
	handler := func(_ sqlpb.SqlDataService_StreamSqlDataServer) error {
		return fmt.Errorf("simulated connection failure")
	}
	addr, cleanup := startMockServer(t, handler)
	defer cleanup()

	ctx := context.Background()
	d, err := newTestDialer(ctx, addr, 45*time.Minute)
	if err != nil {
		t.Fatalf("NewDialer failed: %v", err)
	}
	defer d.Close()

	conn, err := d.Dial(ctx, "proj:reg:inst", WithSQLData())
	if err != nil {
		// If Dial fails, that's also acceptable (e.g. if Send fails synchronously)
		return
	}
	defer conn.Close()

	// If Dial succeeded, Read must fail
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("Read expected error, got nil")
	}
}

func TestDialerWithSqlData_StreamInterruption(t *testing.T) {
	handler := func(stream sqlpb.SqlDataService_StreamSqlDataServer) error {
		// Handshake
		if _, err := stream.Recv(); err != nil {
			return err
		}
		// Receive one data message
		req, err := stream.Recv()
		if err != nil {
			return err
		}
		// Echo it back
		if data := req.GetData(); data != nil {
			err := stream.Send(&sqlpb.StreamSqlDataResponse{
				Message: &sqlpb.StreamSqlDataResponse_Data{
					Data: &sqlpb.DataPacket{
						Data: data.GetData(),
					},
				},
			})

			if err != nil {
				return err
			}
		}

		// Then fail
		return fmt.Errorf("simulated interruption")
	}
	addr, cleanup := startMockServer(t, handler)
	defer cleanup()

	ctx := context.Background()
	d, err := newTestDialer(ctx, addr, 45*time.Minute)

	if err != nil {
		t.Fatalf("NewDialer failed: %v", err)
	}
	defer d.Close()

	conn, err := d.Dial(ctx, "proj:reg:inst", WithSQLData())
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer conn.Close()

	msg := []byte("hello")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	// Next read should fail
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("Read expected error, got nil")
	}
}

func TestDialerWithSqlData_ClientCancellation(t *testing.T) {
	handler := func(stream sqlpb.SqlDataService_StreamSqlDataServer) error {
		for {
			req, err := stream.Recv()
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return err
			}
			data := req.GetData()
			if data != nil {
				err := stream.Send(&sqlpb.StreamSqlDataResponse{
					Message: &sqlpb.StreamSqlDataResponse_Data{
						Data: &sqlpb.DataPacket{
							Data: data.GetData(),
						},
					},
				})
				if err != nil {
					return err
				}
			}
		}
	}
	addr, cleanup := startMockServer(t, handler)
	defer cleanup()

	ctx := context.Background()
	d, err := newTestDialer(ctx, addr, 45*time.Minute)
	if err != nil {
		t.Fatalf("NewDialer failed: %v", err)
	}
	defer d.Close()

	// Use a cancellable context for Dial.
	dialCtx, cancel := context.WithCancel(context.Background())
	conn, err := d.Dial(dialCtx, "proj:reg:inst", WithSQLData())
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer conn.Close()

	cancel()

	// Read/Write should still work because cancel only affects dialing
	msg := []byte("hello")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("Write failed after cancel: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("Read failed after cancel: %v", err)
	}
	if string(buf) != string(msg) {
		t.Errorf("Got %q, want %q", string(buf), string(msg))
	}
}

func TestDialerWithSqlData_ConcurrentConnections(t *testing.T) {
	handler := func(stream sqlpb.SqlDataService_StreamSqlDataServer) error {
		for {
			req, err := stream.Recv()
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return err
			}
			data := req.GetData()
			if data != nil {
				err := stream.Send(&sqlpb.StreamSqlDataResponse{
					Message: &sqlpb.StreamSqlDataResponse_Data{
						Data: &sqlpb.DataPacket{
							Data: data.GetData(),
						},
					},
				})
				if err != nil {
					return err
				}
			}
		}
	}
	addr, cleanup := startMockServer(t, handler)
	defer cleanup()

	ctx := context.Background()
	d, err := newTestDialer(ctx, addr, 45*time.Minute)
	if err != nil {
		t.Fatalf("NewDialer failed: %v", err)
	}
	defer d.Close()

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := d.Dial(ctx, "proj:reg:inst", WithSQLData())
			if err != nil {
				t.Errorf("Dial failed: %v", err)
				return
			}
			defer conn.Close()

			msg := []byte("hello")
			if _, err := conn.Write(msg); err != nil {
				t.Errorf("Write failed: %v", err)
				return
			}
			buf := make([]byte, len(msg))
			if _, err := io.ReadFull(conn, buf); err != nil {
				t.Errorf("Read failed: %v", err)
				return
			}
			if string(buf) != string(msg) {
				t.Errorf("Got %q, want %q", string(buf), string(msg))
			}
		}()
	}
	wg.Wait()
}

func TestDialerWithSqlData_HeadersAndSequence(t *testing.T) {
	errCh := make(chan error, 1)
	handler := func(stream sqlpb.SqlDataService_StreamSqlDataServer) error {
		defer close(errCh)
		md, ok := metadata.FromIncomingContext(stream.Context())
		if !ok {
			err := fmt.Errorf("no metadata")
			errCh <- err
			return err
		}

		// 1. Assert x-goog-user-project is not sent to avoid duplicate project header with x-goog-request-params
		userProjects := md.Get("x-goog-user-project")
		if len(userProjects) != 0 {
			err := fmt.Errorf("metadata x-goog-user-project mismatch: got %v, want empty to prevent conflict with x-goog-request-params", userProjects)
			errCh <- err
			return err
		}

		// 1b. Assert user-agent
		userAgents := md.Get("user-agent")
		foundUA := false
		for _, ua := range userAgents {
			if strings.Contains(ua, "userAgent") {
				foundUA = true
				break
			}
		}
		if !foundUA {
			err := fmt.Errorf("metadata user-agent mismatch: got %v, want to contain userAgent", userAgents)
			errCh <- err
			return err
		}

		// 2. Assert x-goog-request-params (location_id)
		params := md.Get("x-goog-request-params")
		// NOTE: Current implementation of connectNoIP does NOT explicitly set this header in the context
		// passed to StreamSqlData. Unless GAPIC does it (which is unlikely for client-streaming init),
		// this might fail.
		// We expect location_id=locations/reg
		foundLocation := false
		for _, p := range params {
			if strings.Contains(p, "location_id=locations/reg") {
				foundLocation = true
				break
			}
		}
		if !foundLocation {
			err := fmt.Errorf("metadata x-goog-request-params mismatch: got %v, want location_id=locations/reg", params)
			errCh <- err
			return err
		}

		// 3. Verify StartSession in first message
		req, err := stream.Recv()
		if err != nil {
			errCh <- err
			return err
		}
		settings := req.GetStartSession()
		if settings == nil {
			err := fmt.Errorf("expected StartSession in first message, got %v", req)
			errCh <- err
			return err
		}

		// Verify instance ID
		inst := settings.GetInstanceId()
		if inst != "projects/proj/instances/inst" {
			err := fmt.Errorf("StartSession instance mismatch: got %q, want projects/proj/instances/inst", inst)
			errCh <- err
			return err
		}

		return nil
	}
	addr, cleanup := startMockServer(t, handler)
	defer cleanup()

	ctx := context.Background()
	d, err := NewDialer(ctx,
		WithQuotaProject("quotaProj"),
		WithTokenSource(mock.EmptyTokenSource{}),
		WithDefaultDialOptions(WithSQLData()),
		WithSQLDataDialer(sqldataclient.NewGrpcDialer(addr, nil, "quotaProj", nullLogger{}, true, 45*time.Minute, "userAgent")))

	if err != nil {
		t.Fatalf("NewDialer failed: %v", err)
	}
	defer d.Close()

	conn, err := d.Dial(ctx, "proj:reg:inst", WithSQLData())
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}

	// Wait for server verification
	if err := <-errCh; err != nil {
		t.Fatalf("Server verification failed: %v", err)
	}
	conn.Close()
}

func TestDialerWithSqlData_LargePayload(t *testing.T) {
	// 10MB payload
	payloadSize := 10 * 1024 * 1024
	largeData := make([]byte, payloadSize)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	handler := func(stream sqlpb.SqlDataService_StreamSqlDataServer) error {
		// Handshake
		if _, err := stream.Recv(); err != nil {
			return err
		}
		// Echo loop
		for {
			req, err := stream.Recv()
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return err
			}
			data := req.GetData()
			if data != nil {
				err := stream.Send(&sqlpb.StreamSqlDataResponse{
					Message: &sqlpb.StreamSqlDataResponse_Data{
						Data: &sqlpb.DataPacket{
							Data: data.GetData(),
						},
					},
				})
				if err != nil {
					return err
				}
			}
		}
	}
	addr, cleanup := startMockServer(t, handler)
	defer cleanup()

	ctx := context.Background()
	d, err := newTestDialer(ctx, addr, 45*time.Minute)
	if err != nil {
		t.Fatalf("NewDialer failed: %v", err)
	}
	defer d.Close()

	conn, err := d.Dial(ctx, "proj:reg:inst", WithSQLData())
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer conn.Close()

	go func() {
		if _, err := conn.Write(largeData); err != nil {
			t.Errorf("Write failed: %v", err)
		}
	}()

	recvBuf := make([]byte, payloadSize)
	if _, err := io.ReadFull(conn, recvBuf); err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	for i := range recvBuf {
		if recvBuf[i] != largeData[i] {
			t.Fatalf("Received data mismatch at index %d", i)
		}
	}
}

func TestDialerWithSqlDataTimeout(t *testing.T) {
	// A handler that blocks on Recv, so it never completes.
	handler := func(stream sqlpb.SqlDataService_StreamSqlDataServer) error {
		_, _ = stream.Recv() // read initial settings
		time.Sleep(5 * time.Second)
		return nil
	}

	addr, cleanup := startMockServer(t, handler)
	defer cleanup()

	ctx := context.Background()
	// Set a short timeout
	dialTimeout := 500 * time.Millisecond
	d, err := newTestDialer(ctx, addr, dialTimeout)
	if err != nil {
		t.Fatalf("NewDialer failed: %v", err)
	}
	defer d.Close()

	// 4. Connect
	conn, err := d.Dial(ctx, "proj:reg:inst", WithSQLData())
	if err != nil {
		// If dial failed, check the error
		if !strings.Contains(strings.ToLower(err.Error()), "deadline") {
			t.Fatalf("expected deadline exceeded error during dial, got: %v", err)
		}
		return
	}
	defer conn.Close()

	// If Dial succeeded, Read should fail due to timeout
	_, err = conn.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("expected Read to fail due to timeout, but it succeeded")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "deadline") {
		t.Fatalf("expected deadline exceeded error during read, got: %v", err)
	}
}

func TestDialerWithSqlData_DialCancellation(t *testing.T) {
	handler := func(_ sqlpb.SqlDataService_StreamSqlDataServer) error {
		return nil
	}
	addr, cleanup := startMockServer(t, handler)
	defer cleanup()

	ctx := context.Background()
	d, err := newTestDialer(ctx, addr, 45*time.Minute)
	if err != nil {
		t.Fatalf("NewDialer failed: %v", err)
	}
	defer d.Close()

	// Use a context that is already cancelled.
	dialCtx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = d.Dial(dialCtx, "proj:reg:inst", WithSQLData())
	if err == nil {
		t.Fatal("Dial expected error with cancelled context, got nil")
	}
	if !strings.Contains(err.Error(), "context canceled") {
		t.Errorf("Expected context canceled error, got: %v", err)
	}
}

func newTestDialer(ctx context.Context, addr string, dialTimeout time.Duration) (*Dialer, error) {
	opts := []Option{
		WithTokenSource(mock.EmptyTokenSource{}),
		WithDefaultDialOptions(WithSQLData()),
		WithSQLDataDialer(sqldataclient.NewGrpcDialer(addr, nil, "", nullLogger{}, true, dialTimeout, "")),
	}

	return NewDialer(ctx, opts...)
}

func TestDialerWithSqlData_ResourceExhaustedCooldown(t *testing.T) {
	var callCount int
	var mu sync.Mutex
	handler := func(stream sqlpb.SqlDataService_StreamSqlDataServer) error {
		mu.Lock()
		callCount++
		mu.Unlock()
		if _, err := stream.Recv(); err != nil {
			return err
		}
		return status.Error(codes.ResourceExhausted, "resource busy")
	}
	addr, cleanup := startMockServer(t, handler)
	defer cleanup()

	ctx := context.Background()
	cooldown := 500 * time.Millisecond
	d, err := NewDialer(ctx,
		WithTokenSource(mock.EmptyTokenSource{}),
		WithDefaultDialOptions(WithSQLData()),
		WithSQLDataDialer(sqldataclient.NewGrpcDialer(addr, nil, "", nullLogger{}, true, 45*time.Minute, "")),
		WithResourceExhaustedCooldownPeriod(cooldown),
	)
	if err != nil {
		t.Fatalf("NewDialer failed: %v", err)
	}
	defer d.Close()

	// First dial might succeed, if so we must read to get the error
	conn, err := d.Dial(ctx, "proj:reg:inst", WithSQLData())
	if err == nil {
		defer conn.Close()
		_, err = conn.Read(make([]byte, 1))
	}
	if err == nil {
		t.Fatal("expected Dial or Read to fail")
	}
	if !strings.Contains(err.Error(), "resource busy") {
		t.Fatalf("expected resource busy error, got: %v", err)
	}

	mu.Lock()
	if callCount != 1 {
		t.Errorf("expected 1 call to server, got %d", callCount)
	}
	mu.Unlock()

	// Second dial immediately should fail with ResourceExhaustedError (cooldown active)
	// and should NOT call the server
	_, err = d.Dial(ctx, "proj:reg:inst", WithSQLData())
	if err == nil {
		t.Fatal("expected Dial to fail during cooldown")
	}
	var reErr *errtype.ResourceExhaustedError
	if !errors.As(err, &reErr) {
		t.Fatalf("expected ResourceExhaustedError, got: %T (%v)", err, err)
	}
	if !strings.Contains(err.Error(), "cooldown active") {
		t.Errorf("expected cooldown active message, got: %v", err)
	}

	mu.Lock()
	if callCount != 1 {
		t.Errorf("expected still 1 call to server (cooldown should prevent call), got %d", callCount)
	}
	mu.Unlock()

	// Wait for cooldown to expire (max backoff for attempt 1 is cooldown * 1.618)
	time.Sleep(2 * cooldown)

	// Third dial might succeed, if so we must read to get the error
	conn2, err := d.Dial(ctx, "proj:reg:inst", WithSQLData())
	if err == nil {
		defer conn2.Close()
		_, err = conn2.Read(make([]byte, 1))
	}
	if err == nil {
		t.Fatal("expected Dial or Read to fail after cooldown")
	}
	if errors.As(err, &reErr) {
		t.Fatalf("expected server error, got cooldown error: %v", err)
	}
	if !strings.Contains(err.Error(), "resource busy") {
		t.Fatalf("expected resource busy error from server, got: %v", err)
	}

	mu.Lock()
	if callCount != 2 {
		t.Errorf("expected 2 calls to server after cooldown, got %d", callCount)
	}
	mu.Unlock()
}

func TestDialerWithSqlData_ResourceExhaustedCooldown_StreamError(t *testing.T) {
	var callCount int
	var mu sync.Mutex
	handler := func(stream sqlpb.SqlDataService_StreamSqlDataServer) error {
		mu.Lock()
		callCount++
		mu.Unlock()
		// Handshake
		if _, err := stream.Recv(); err != nil {
			return err
		}
		// Return error on first actual data stream read (or just close stream with error)
		return status.Error(codes.ResourceExhausted, "resource busy")
	}
	addr, cleanup := startMockServer(t, handler)
	defer cleanup()

	ctx := context.Background()
	cooldown := 500 * time.Millisecond
	d, err := NewDialer(ctx,
		WithTokenSource(mock.EmptyTokenSource{}),
		WithDefaultDialOptions(WithSQLData()),
		WithSQLDataDialer(sqldataclient.NewGrpcDialer(addr, nil, "", nullLogger{}, true, 45*time.Minute, "")),
		WithResourceExhaustedCooldownPeriod(cooldown),
	)
	if err != nil {
		t.Fatalf("NewDialer failed: %v", err)
	}
	defer d.Close()

	// First dial should succeed (handshake succeeds)
	conn, err := d.Dial(ctx, "proj:reg:inst", WithSQLData())
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer conn.Close()

	// First read should fail with ResourceExhausted
	_, err = conn.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("expected Read to fail")
	}
	if !strings.Contains(err.Error(), "resource busy") {
		t.Fatalf("expected resource busy error, got: %v", err)
	}

	mu.Lock()
	if callCount != 1 {
		t.Errorf("expected 1 call to server, got %d", callCount)
	}
	mu.Unlock()

	// Second dial immediately should fail with ResourceExhaustedError (cooldown active)
	_, err = d.Dial(ctx, "proj:reg:inst", WithSQLData())
	if err == nil {
		t.Fatal("expected Dial to fail during cooldown")
	}
	var reErr *errtype.ResourceExhaustedError
	if !errors.As(err, &reErr) {
		t.Fatalf("expected ResourceExhaustedError, got: %T (%v)", err, err)
	}

	mu.Lock()
	if callCount != 1 {
		t.Errorf("expected still 1 call to server, got %d", callCount)
	}
	mu.Unlock()

	// Wait for cooldown to expire (max backoff for attempt 1 is cooldown * 1.618)
	time.Sleep(2 * cooldown)

	// Third dial should call the server again
	conn2, err := d.Dial(ctx, "proj:reg:inst", WithSQLData())
	if err != nil {
		t.Fatalf("Dial failed after cooldown: %v", err)
	}
	defer conn2.Close()

	// Perform a read to ensure the server handler has run and failed
	_, err = conn2.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("expected Read to fail after cooldown")
	}
	if !strings.Contains(err.Error(), "resource busy") {
		t.Fatalf("expected resource busy error, got: %v", err)
	}

	mu.Lock()
	if callCount != 2 {
		t.Errorf("expected 2 calls to server after cooldown, got %d", callCount)
	}
	mu.Unlock()
}

func TestDialerWithSqlData_ResourceExhaustedBackoff(t *testing.T) {
	var succeed bool
	var succeedMu sync.Mutex
	handler := func(stream sqlpb.SqlDataService_StreamSqlDataServer) error {
		// Read initial connection settings (StartSession)
		req, err := stream.Recv()
		if err != nil {
			return err
		}
		if req.GetStartSession() == nil {
			return fmt.Errorf("expected StartSession, got %v", req)
		}

		succeedMu.Lock()
		s := succeed
		succeedMu.Unlock()

		if !s {
			return status.Error(codes.ResourceExhausted, "resource busy")
		}

		// Echo loop
		for {
			req, err := stream.Recv()
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return err
			}

			data := req.GetData()
			if data != nil {
				// Echo back
				err := stream.Send(&sqlpb.StreamSqlDataResponse{
					Message: &sqlpb.StreamSqlDataResponse_Data{
						Data: &sqlpb.DataPacket{
							Data: data.GetData(),
						},
					},
				})
				if err != nil {
					return err
				}
			}
		}
	}
	addr, cleanup := startMockServer(t, handler)
	defer cleanup()

	ctx := context.Background()
	cooldown := 500 * time.Millisecond
	d, err := NewDialer(ctx,
		WithTokenSource(mock.EmptyTokenSource{}),
		WithDefaultDialOptions(WithSQLData()),
		WithSQLDataDialer(sqldataclient.NewGrpcDialer(addr, nil, "", nullLogger{}, true, 45*time.Minute, "")),
		WithResourceExhaustedCooldownPeriod(cooldown),
	)
	if err != nil {
		t.Fatalf("NewDialer failed: %v", err)
	}
	defer d.Close()

	instName := "proj:reg:inst"
	cn, _ := instance.ParseConnName(instName)
	key := createKey(cn)

	// Helper to get state
	getState := func() *sqlDataConnState {
		d.lock.RLock()
		state := d.sqlDataConnState[key]
		d.lock.RUnlock()
		return state
	}

	// 1. Initial State
	state := getState()
	if state != nil {
		t.Fatalf("expected state to be nil before first dial, got: %+v", state)
	}

	// 2. First failure (Dial succeeds, Read fails)
	conn, err := d.Dial(ctx, instName, WithSQLData())
	if err != nil {
		t.Fatalf("first Dial failed: %v", err)
	}
	_, err = conn.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("expected Read to fail")
	}
	conn.Close()

	state = getState()
	if state == nil {
		t.Fatal("expected state to be initialized after failure")
	}
	state.mu.Lock()
	counter := state.backoffCounter
	cooldownUntil := state.cooldownUntil
	state.mu.Unlock()

	if counter != 1 {
		t.Errorf("expected backoffCounter to be 1, got: %d", counter)
	}
	if cooldownUntil.Before(time.Now()) {
		t.Errorf("expected cooldownUntil to be in the future, got: %v", cooldownUntil)
	}
	firstCooldownDuration := time.Until(cooldownUntil)
	if firstCooldownDuration < 400*time.Millisecond || firstCooldownDuration > 900*time.Millisecond {
		t.Errorf("expected first cooldown duration to be ~500ms-809ms, got: %v", firstCooldownDuration)
	}

	// 3. Second failure (Dial should fail immediately due to cooldown)
	_, err = d.Dial(ctx, instName, WithSQLData())
	if err == nil {
		t.Fatal("expected Dial to fail during cooldown")
	}

	state.mu.Lock()
	counter = state.backoffCounter
	state.mu.Unlock()
	if counter != 1 {
		t.Errorf("expected backoffCounter to remain 1 during cooldown Dial, got: %d", counter)
	}

	// Wait for cooldown to expire
	time.Sleep(firstCooldownDuration + 50*time.Millisecond)

	// Now dial again, should call server and fail again on read, incrementing counter to 2
	conn2, err := d.Dial(ctx, instName, WithSQLData())
	if err != nil {
		t.Fatalf("second Dial failed: %v", err)
	}
	_, err = conn2.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("expected second Read to fail")
	}
	conn2.Close()

	state.mu.Lock()
	counter = state.backoffCounter
	cooldownUntil = state.cooldownUntil
	state.mu.Unlock()

	if counter != 2 {
		t.Errorf("expected backoffCounter to be 2, got: %d", counter)
	}
	secondCooldownDuration := time.Until(cooldownUntil)
	if secondCooldownDuration < 700*time.Millisecond || secondCooldownDuration > 1400*time.Millisecond {
		t.Errorf("expected second cooldown duration to be ~809ms-1309ms, got: %v", secondCooldownDuration)
	}

	// Wait for second cooldown to expire
	time.Sleep(secondCooldownDuration + 50*time.Millisecond)

	// 4. Success (Dial succeeds, Write/Read succeeds)
	succeedMu.Lock()
	succeed = true
	succeedMu.Unlock()

	conn3, err := d.Dial(ctx, instName, WithSQLData())
	if err != nil {
		t.Fatalf("third Dial failed: %v", err)
	}
	defer conn3.Close()

	// Write and Read to ensure it is successful
	want := []byte("test")
	if _, err := conn3.Write(want); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn3, got); err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	// Verify state is reset
	state = getState()
	if state == nil {
		t.Fatal("expected state to exist")
	}
	state.mu.Lock()
	counter = state.backoffCounter
	cooldownUntil = state.cooldownUntil
	state.mu.Unlock()

	if counter != 0 {
		t.Errorf("expected backoffCounter to be reset to 0, got: %d", counter)
	}
	if !cooldownUntil.IsZero() {
		t.Errorf("expected cooldownUntil to be cleared (zero time), got: %v", cooldownUntil)
	}
}
