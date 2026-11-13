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
	"net"
	"strings"
	"sync"
	"time"

	"cloud.google.com/go/auth"
	"cloud.google.com/go/auth/oauth2adapt"
	"cloud.google.com/go/cloudsqlconn/debug"
	"cloud.google.com/go/cloudsqlconn/instance"
	sqlgapic "cloud.google.com/go/sql/apiv1beta4"
	sqlpb "cloud.google.com/go/sql/apiv1beta4/sqlpb"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/encoding/protowire"
)

const (
	// maxMsgSize is the maximum gRPC send/receive message size (100 MiB).
	maxMsgSize = 100 * 1024 * 1024

	// streamCancelDelay is the grace period before canceling streamCtx on Close,
	// giving CloseSend() time to flush the closing frame over gRPC.
	streamCancelDelay = 5 * time.Second
)

// errDialerClosed is returned when ConnectSQLDataService is called on a closed GrpcDialer.
var errDialerClosed = errors.New("sql data dialer is closed")

// Dialer is the interface that wraps the ConnectSQLDataService and Close methods.
type Dialer interface {
	ConnectSQLDataService(ctx context.Context, cn instance.ConnName, autoIAM bool) (conn net.Conn, err error)
	Close() error
}

// NewGrpcDialer returns a new GrpcDialer configured to use the given endpoint.
func NewGrpcDialer(endpoint string, tokenProvider auth.TokenProvider, quotaProject string, logger debug.ContextLogger, timeout time.Duration, userAgent string, clientOpts ...option.ClientOption) *GrpcDialer {
	return &GrpcDialer{
		endpoint:      endpoint,
		tokenProvider: tokenProvider,
		logger:        logger,
		timeout:       timeout,
		quotaProject:  quotaProject,
		userAgent:     userAgent,
		clientOpts:    clientOpts,
	}
}

// GrpcDialer is a Dialer that connects to the SqlDataService via gRPC.
type GrpcDialer struct {
	endpoint      string
	tokenProvider auth.TokenProvider
	logger        debug.ContextLogger
	// timeout is the maximum lifetime for the entire gRPC stream, not the
	// dial handshake timeout. Zero or negative disables the per-stream deadline.
	timeout time.Duration

	// sqlDataClientMu synchronizes access to sqlDataClient and closed.
	sqlDataClientMu sync.RWMutex
	sqlDataClient   *sqlgapic.SqlDataClient
	closed          bool
	quotaProject    string
	userAgent       string
	clientOpts      []option.ClientOption
}

// Close closes the underlying gRPC client connection.
func (d *GrpcDialer) Close() error {
	if d == nil {
		return nil
	}
	d.sqlDataClientMu.RLock()
	closed := d.closed
	d.sqlDataClientMu.RUnlock()
	if closed {
		// client is already closed. Return early.
		return nil
	}

	d.sqlDataClientMu.Lock()
	defer d.sqlDataClientMu.Unlock()
	if d.closed {
		return nil
	}
	d.closed = true
	if d.sqlDataClient == nil {
		return nil
	}
	err := d.sqlDataClient.Close()
	d.sqlDataClient = nil
	return err
}

func (d *GrpcDialer) initSQLDataClient(ctx context.Context) (*sqlgapic.SqlDataClient, error) {
	d.sqlDataClientMu.RLock()
	c, closed := d.sqlDataClient, d.closed
	d.sqlDataClientMu.RUnlock()
	if closed {
		return nil, errDialerClosed
	}
	if c != nil {
		// client is already initialized. Return early.
		return c, nil
	}

	// Client is nil. Initialize the client.
	d.sqlDataClientMu.Lock()
	defer d.sqlDataClientMu.Unlock()

	if d.closed {
		return nil, errDialerClosed
	}
	if c := d.sqlDataClient; c != nil {
		// Client was initialized between releasing the read lock and acquiring
		// the write lock.
		return c, nil
	}

	var clientOpts []option.ClientOption
	clientOpts = append(clientOpts,
		option.WithGRPCDialOption(grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(maxMsgSize),
			grpc.MaxCallSendMsgSize(maxMsgSize),
		)),
	)
	if d.userAgent != "" {
		clientOpts = append(clientOpts, option.WithUserAgent(d.userAgent))
	}
	if d.quotaProject != "" {
		clientOpts = append(clientOpts, option.WithQuotaProject(d.quotaProject))
	}
	if d.tokenProvider != nil {
		ts := oauth2adapt.TokenSourceFromTokenProvider(d.tokenProvider)
		clientOpts = append(clientOpts, option.WithTokenSource(ts))
	}
	clientOpts = append(clientOpts, d.clientOpts...)

	if d.endpoint != "" {
		endpoint := strings.TrimPrefix(d.endpoint, "https://")
		if _, _, err := net.SplitHostPort(endpoint); err != nil {
			endpoint = net.JoinHostPort(endpoint, "443")
		}
		clientOpts = append(clientOpts, option.WithEndpoint(endpoint))
	}

	c, err := sqlgapic.NewSqlDataClient(ctx, clientOpts...)
	if err != nil {
		return nil, err
	}
	d.sqlDataClient = c
	return c, nil
}

// ConnectSQLDataService connects to the SqlDataService for the given connection name.
func (d *GrpcDialer) ConnectSQLDataService(ctx context.Context, cn instance.ConnName, autoIAM bool) (conn net.Conn, err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// ctx is the context with a 30 second timeout, which would allow the stream to connect.
	// it should not be used as the context for the grpc stream call, which will run for
	// more than the initial connection timeout.
	// We're leaving the ctx argument in for future use.

	c, err := d.initSQLDataClient(ctx)
	if err != nil {
		return nil, err
	}
	// Do not derive streamCtx from ctx: callers frequently cancel the Dial
	// context (or apply a short dial timeout) once Dial returns a net.Conn,
	// whereas the gRPC stream must remain alive for the lifetime of the conn.
	var (
		streamCtx context.Context
		cancel    context.CancelFunc
	)
	if d.timeout > 0 {
		d.logger.Debugf(ctx, "Setting timeout: %v", d.timeout)
		streamCtx, cancel = context.WithTimeout(context.Background(), d.timeout)
	} else {
		streamCtx, cancel = context.WithCancel(context.Background())
	}

	// Linked context will cancel the stream only while Dial is in progress.
	dialDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			cancel()
		case <-dialDone:
		}
	}()
	defer close(dialDone)

	// routing_parameters: [ { field: "instance_id" }, { field: "location_id" } ]
	instanceID := fmt.Sprintf("projects/%s/instances/%s", cn.Project(), cn.Name())
	streamCtx = metadata.AppendToOutgoingContext(streamCtx,
		"x-goog-request-params", fmt.Sprintf("location_id=locations/%s&instance_id=%s", cn.Region(), instanceID))

	// If quota-project cli flag is set, add the request header.
	if d.quotaProject != "" {
		streamCtx = metadata.AppendToOutgoingContext(streamCtx, "x-goog-user-project", d.quotaProject)
	}

	stream, err := c.StreamSqlData(streamCtx)
	if err != nil {
		cancel()
		return nil, err
	}
	startSession := &sqlpb.StartSession{
		LocationId: fmt.Sprintf("locations/%s", cn.Region()),
		InstanceId: instanceID,
	}
	if autoIAM {
		// TODO: Replace this reflection code with startSession.AuthenticationType = sqlpb.StartSession_AUTO_IAM_AUTHENTICATION
		// (or startSession.SetAutoIAM(true)) once the published cloud.google.com/go/sql library includes this field.
		// Field 4: authentication_type (varint) = AUTO_IAM_AUTHENTICATION (2).
		// Set unknown field so that the wire format includes authentication_type
		// even if the generated proto struct does not yet expose field 4.
		raw := startSession.ProtoReflect().GetUnknown()
		raw = protowire.AppendTag(raw, 4, protowire.VarintType)
		raw = protowire.AppendVarint(raw, 2)
		startSession.ProtoReflect().SetUnknown(raw)
	}
	err = stream.Send(&sqlpb.StreamSqlDataRequest{
		Message: &sqlpb.StreamSqlDataRequest_StartSession{
			StartSession: startSession,
		},
	})
	if err != nil {
		cancel()
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		cancel()
		return nil, err
	}
	d.logger.Debugf(ctx, "Dialing via SqlDataService: %v", cn.Name())
	return &streamConn{
		stream: stream,
		cancel: cancel,
		logger: d.logger,
	}, nil
}

// streamConn wraps the gRPC stream to implement net.Conn
type streamConn struct {
	stream     sqlpb.SqlDataService_StreamSqlDataClient
	cancel     context.CancelFunc
	readBuf    []byte
	readOffset int
	logger     debug.ContextLogger
}

func (c *streamConn) Read(b []byte) (n int, err error) {
	if c.readOffset < len(c.readBuf) {
		n = copy(b, c.readBuf[c.readOffset:])
		c.readOffset += n
		return n, nil
	}
	for {
		msg, err := c.stream.Recv()
		if err != nil {
			// This could be io.EOF or a gRPC error
			return 0, err
		}

		if msg.GetData() == nil {
			// Ignore unknown messages (e.g. SessionMetadata).
			c.logger.Debugf(context.Background(), "Received unknown message %v", msg)
			continue
		}
		c.readBuf = msg.GetData().GetData()
		c.readOffset = 0
		if len(c.readBuf) == 0 {
			continue
		}
		n = copy(b, c.readBuf)
		c.readOffset = n
		return n, nil
	}
}

func (c *streamConn) Write(b []byte) (n int, err error) {
	if len(b) == 0 {
		return 0, nil
	}
	err = c.stream.Send(&sqlpb.StreamSqlDataRequest{
		Message: &sqlpb.StreamSqlDataRequest_Data{
			Data: &sqlpb.DataPacket{
				Data: b,
			},
		},
	})
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *streamConn) Close() error {
	if c == nil {
		return nil
	}
	err := c.stream.CloseSend()
	if c.cancel != nil {
		time.AfterFunc(streamCancelDelay, c.cancel)
	}
	return err
}

func (c *streamConn) LocalAddr() net.Addr {
	return localAddr{}
}

func (c *streamConn) RemoteAddr() net.Addr {
	return remoteAddr{}
}

// SetDeadline is a no-op: gRPC streams do not support per-read/per-write
// net.Conn deadlines. Overall stream lifetime is bounded instead by the
// streamCtx deadline (WithSQLDataStreamTimeout).
func (c *streamConn) SetDeadline(_ time.Time) error {
	return nil
}

// SetReadDeadline is a no-op; see SetDeadline.
func (c *streamConn) SetReadDeadline(_ time.Time) error {
	return nil
}

// SetWriteDeadline is a no-op; see SetDeadline.
func (c *streamConn) SetWriteDeadline(_ time.Time) error {
	return nil
}

type localAddr struct{}

func (la localAddr) Network() string { return "grpc" }
func (la localAddr) String() string  { return "local" }

type remoteAddr struct{}

func (ra remoteAddr) Network() string { return "grpc" }
func (ra remoteAddr) String() string  { return "remote" }
