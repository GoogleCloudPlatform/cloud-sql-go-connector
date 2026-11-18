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

package sqldataclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"cloud.google.com/go/cloudsqlconn/errtype"
	"cloud.google.com/go/cloudsqlconn/instance"
	sqlpb "cloud.google.com/go/sql/apiv1beta4/sqlpb"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

const testConnName = "my-project:my-region:my-instance"

type testLogger struct{}

func (testLogger) Debugf(context.Context, string, ...any) {}

type fakeSQLDataServiceServer struct {
	sqlpb.UnimplementedSqlDataServiceServer
	onStreamSQLData func(sqlpb.SqlDataService_StreamSqlDataServer) error
}

//nolint:revive
func (f *fakeSQLDataServiceServer) StreamSqlData(stream sqlpb.SqlDataService_StreamSqlDataServer) error {
	if f.onStreamSQLData != nil {
		return f.onStreamSQLData(stream)
	}
	return nil
}

func startTestServer(t *testing.T, handler func(sqlpb.SqlDataService_StreamSqlDataServer) error) (string, func()) {
	t.Helper()
	lis, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	sqlpb.RegisterSqlDataServiceServer(s, &fakeSQLDataServiceServer{onStreamSQLData: handler})
	go func() { _ = s.Serve(lis) }()
	return lis.Addr().String(), func() { s.Stop() }
}

func newTestGrpcDialer(addr string, cooldown time.Duration) *GrpcDialer {
	return NewGrpcDialer(
		addr, nil, "", testLogger{}, 5*time.Minute, "", cooldown,
		option.WithoutAuthentication(),
		option.WithGRPCDialOption(grpc.WithTransportCredentials(insecure.NewCredentials())),
	)
}

func TestIsResourceExhaustedError(t *testing.T) {
	grpcRE := status.Error(codes.ResourceExhausted, "busy")
	wrappedGrpcRE := fmt.Errorf("wrapped: %w", grpcRE)
	reErr := errtype.NewResourceExhaustedError("cooldown active", testConnName, nil)
	reErrWrapped := errtype.NewResourceExhaustedError("cooldown active", testConnName, grpcRE)

	tcs := []struct {
		desc string
		err  error
		want bool
	}{
		{desc: "nil", err: nil, want: false},
		{desc: "generic error", err: errors.New("boom"), want: false},
		{desc: "grpc unavailable", err: status.Error(codes.Unavailable, "down"), want: false},
		{desc: "grpc resource exhausted", err: grpcRE, want: true},
		{desc: "wrapped grpc resource exhausted", err: wrappedGrpcRE, want: true},
		{desc: "errtype ResourceExhaustedError without cause", err: reErr, want: true},
		{desc: "errtype ResourceExhaustedError with cause", err: reErrWrapped, want: true},
	}

	for _, tc := range tcs {
		t.Run(tc.desc, func(t *testing.T) {
			if got := IsResourceExhaustedError(tc.err); got != tc.want {
				t.Errorf("IsResourceExhaustedError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestGrpcDialer_ResourceExhaustedBackoffState(t *testing.T) {
	var succeed bool
	var mu sync.Mutex
	handler := func(stream sqlpb.SqlDataService_StreamSqlDataServer) error {
		if _, err := stream.Recv(); err != nil {
			return err
		}
		mu.Lock()
		s := succeed
		mu.Unlock()
		if !s {
			return status.Error(codes.ResourceExhausted, "resource busy")
		}
		for {
			req, err := stream.Recv()
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return err
			}
			if data := req.GetData(); data != nil {
				if err := stream.Send(&sqlpb.StreamSqlDataResponse{
					Message: &sqlpb.StreamSqlDataResponse_Data{
						Data: &sqlpb.DataPacket{Data: data.GetData()},
					},
				}); err != nil {
					return err
				}
			}
		}
	}
	addr, cleanup := startTestServer(t, handler)
	defer cleanup()

	cooldown := 200 * time.Millisecond
	sd := newTestGrpcDialer(addr, cooldown)
	defer sd.Close()

	cn, err := instance.ParseConnName(testConnName)
	if err != nil {
		t.Fatalf("ParseConnName failed: %v", err)
	}

	getState := func() *sqlDataConnState {
		sd.mu.RLock()
		defer sd.mu.RUnlock()
		return sd.sqlDataConnState[stateKey(cn)]
	}

	if state := getState(); state != nil {
		t.Fatalf("expected state to be nil before first dial, got: %+v", state)
	}

	var errCount, successCount int
	onSuccess := func() { successCount++ }
	onError := func(error) { errCount++ }

	ctx := context.Background()
	conn, err := sd.ConnectSQLDataService(ctx, cn, false, onSuccess, onError)
	if err != nil {
		t.Fatalf("first ConnectSQLDataService failed: %v", err)
	}
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected first Read to fail")
	}
	conn.Close()

	if errCount != 1 {
		t.Errorf("expected onError count 1, got %d", errCount)
	}

	state := getState()
	if state == nil {
		t.Fatal("expected state to be initialized after first ConnectSQLDataService")
	}
	state.mu.Lock()
	counter := state.backoffCounter
	cooldownUntil := state.cooldownUntil
	state.mu.Unlock()

	if counter != 1 {
		t.Errorf("expected backoffCounter = 1, got %d", counter)
	}
	firstDur := time.Until(cooldownUntil)
	if firstDur < 100*time.Millisecond || firstDur > 400*time.Millisecond {
		t.Errorf("expected first cooldown duration ~200ms-324ms, got %v", firstDur)
	}

	// While in cooldown, ConnectSQLDataService fails immediately without invoking onError.
	_, err = sd.ConnectSQLDataService(ctx, cn, false, onSuccess, onError)
	var reErr *errtype.ResourceExhaustedError
	if !errors.As(err, &reErr) {
		t.Fatalf("expected ResourceExhaustedError during cooldown, got %v", err)
	}
	if errCount != 1 {
		t.Errorf("expected onError count still 1 during cooldown, got %d", errCount)
	}

	time.Sleep(firstDur + 30*time.Millisecond)

	// Second failure increments backoffCounter to 2.
	conn2, err := sd.ConnectSQLDataService(ctx, cn, false, onSuccess, onError)
	if err != nil {
		t.Fatalf("second ConnectSQLDataService failed: %v", err)
	}
	if _, err := conn2.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected second Read to fail")
	}
	conn2.Close()

	state.mu.Lock()
	counter = state.backoffCounter
	state.mu.Unlock()

	if counter != 2 {
		t.Errorf("expected backoffCounter = 2, got %d", counter)
	}
	if errCount != 2 {
		t.Errorf("expected onError count 2, got %d", errCount)
	}

	// Verify backoff counter caps at 5.
	for i := 0; i < 6; i++ {
		sd.recordResourceExhausted(cn, status.Error(codes.ResourceExhausted, "busy"))
	}
	state.mu.Lock()
	counter = state.backoffCounter
	state.mu.Unlock()
	if counter != 5 {
		t.Errorf("expected backoffCounter to cap at 5, got %d", counter)
	}

	// Clear cooldown and let a connection succeed to verify reset.
	state.mu.Lock()
	state.cooldownUntil = time.Time{}
	state.mu.Unlock()

	mu.Lock()
	succeed = true
	mu.Unlock()

	conn3, err := sd.ConnectSQLDataService(ctx, cn, false, onSuccess, onError)
	if err != nil {
		t.Fatalf("third ConnectSQLDataService failed: %v", err)
	}
	defer conn3.Close()

	msg := []byte("ping")
	if _, err := conn3.Write(msg); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn3, buf); err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if successCount != 1 {
		t.Errorf("expected onSuccess count 1, got %d", successCount)
	}

	state.mu.Lock()
	counter = state.backoffCounter
	cooldownUntil = state.cooldownUntil
	state.mu.Unlock()
	if counter != 0 {
		t.Errorf("expected backoffCounter to reset to 0, got %d", counter)
	}
	if !cooldownUntil.IsZero() {
		t.Errorf("expected cooldownUntil to be zero, got %v", cooldownUntil)
	}
}

func TestGrpcDialer_RepeatedReadErrorsInvokeOnErrorOnce(t *testing.T) {
	handler := func(stream sqlpb.SqlDataService_StreamSqlDataServer) error {
		if _, err := stream.Recv(); err != nil {
			return err
		}
		return status.Error(codes.PermissionDenied, "access denied")
	}
	addr, cleanup := startTestServer(t, handler)
	defer cleanup()

	sd := newTestGrpcDialer(addr, 5*time.Second)
	defer sd.Close()

	cn, err := instance.ParseConnName(testConnName)
	if err != nil {
		t.Fatalf("ParseConnName failed: %v", err)
	}

	var successCount, errCount int
	conn, err := sd.ConnectSQLDataService(
		context.Background(), cn, false,
		func() { successCount++ },
		func(error) { errCount++ },
	)
	if err != nil {
		t.Fatalf("ConnectSQLDataService failed: %v", err)
	}
	defer conn.Close()

	for i := 0; i < 3; i++ {
		if _, err := conn.Read(make([]byte, 1)); err == nil {
			t.Fatalf("Read %d expected error, got nil", i)
		}
	}

	if successCount != 0 {
		t.Errorf("expected onSuccess count 0, got %d", successCount)
	}
	if errCount != 1 {
		t.Errorf("expected onError count 1 across repeated failed Reads, got %d", errCount)
	}
}

type stubConn struct {
	net.Conn
	readFn  func([]byte) (int, error)
	writeFn func([]byte) (int, error)
}

func (s *stubConn) Read(b []byte) (int, error)  { return s.readFn(b) }
func (s *stubConn) Write(b []byte) (int, error) { return s.writeFn(b) }

func TestResourceExhaustedTrackingConn_SingleOutcomeAcrossFlows(t *testing.T) {
	reErr := status.Error(codes.ResourceExhausted, "rate limited")

	t.Run("concurrent Write ResourceExhausted and Read non-RE error", func(t *testing.T) {
		var reCount, successCount, errCount int
		tc := &resourceExhaustedTrackingConn{
			Conn: &stubConn{
				readFn:  func([]byte) (int, error) { return 0, status.Error(codes.Canceled, "canceled") },
				writeFn: func([]byte) (int, error) { return 0, reErr },
			},
			onResourceExhausted: func(error) { reCount++ },
			onSuccess:           func() { successCount++ },
			onError:             func(error) { errCount++ },
		}

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, _ = tc.Write([]byte("startup"))
		}()
		go func() {
			defer wg.Done()
			_, _ = tc.Read(make([]byte, 1))
		}()
		wg.Wait()

		if reCount != 1 {
			t.Errorf("expected onResourceExhausted count 1, got %d", reCount)
		}
		if successCount != 0 {
			t.Errorf("expected onSuccess count 0, got %d", successCount)
		}
		if errCount != 1 {
			t.Errorf("expected onError count 1, got %d", errCount)
		}
	})

	t.Run("repeated ResourceExhausted across Write and Read", func(t *testing.T) {
		var reCount, errCount int
		tc := &resourceExhaustedTrackingConn{
			Conn: &stubConn{
				readFn:  func([]byte) (int, error) { return 0, reErr },
				writeFn: func([]byte) (int, error) { return 0, reErr },
			},
			onResourceExhausted: func(error) { reCount++ },
			onError:             func(error) { errCount++ },
		}

		_, _ = tc.Write([]byte("startup"))
		_, _ = tc.Read(make([]byte, 1))
		_, _ = tc.Read(make([]byte, 1))

		if reCount != 1 {
			t.Errorf("expected onResourceExhausted count 1, got %d", reCount)
		}
		if errCount != 1 {
			t.Errorf("expected onError count 1, got %d", errCount)
		}
	})

	t.Run("mid-stream ResourceExhausted after successful Read triggers cooldown without onError", func(t *testing.T) {
		var calls int
		var reCount, successCount, errCount int
		tc := &resourceExhaustedTrackingConn{
			Conn: &stubConn{
				readFn: func(b []byte) (int, error) {
					calls++
					if calls == 1 {
						b[0] = 'x'
						return 1, nil
					}
					return 0, reErr
				},
				writeFn: func(b []byte) (int, error) { return len(b), nil },
			},
			onResourceExhausted: func(error) { reCount++ },
			onSuccess:           func() { successCount++ },
			onError:             func(error) { errCount++ },
		}

		if _, err := tc.Read(make([]byte, 1)); err != nil {
			t.Fatalf("first Read failed: %v", err)
		}
		if _, err := tc.Read(make([]byte, 1)); !errors.Is(err, reErr) {
			t.Fatalf("second Read expected ResourceExhausted, got %v", err)
		}

		if successCount != 1 {
			t.Errorf("expected onSuccess count 1, got %d", successCount)
		}
		if reCount != 1 {
			t.Errorf("expected onResourceExhausted count 1, got %d", reCount)
		}
		if errCount != 0 {
			t.Errorf("expected onError count 0 after successful dial, got %d", errCount)
		}
	})
}
