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
	"fmt"
	"net"
	"sync"
	"time"

	"cloud.google.com/go/auth"
	"cloud.google.com/go/auth/oauth2adapt"
	"cloud.google.com/go/cloudsqlconn/debug"
	"cloud.google.com/go/cloudsqlconn/instance"
	sqldatapb "cloud.google.com/go/cloudsqlconn/internal/sqldata"
	sqldatagrpcpb "cloud.google.com/go/cloudsqlconn/internal/sqldatagrpc"
	"google.golang.org/grpc"
	grpccreds "google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/credentials/oauth"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
)

// Dialer is the interface that wraps the ConnectSQLDataService and Close methods.
type Dialer interface {
	ConnectSQLDataService(ctx context.Context, cn instance.ConnName) (conn net.Conn, err error)
	Close() error
}

// NewGrpcDialer returns a new GrpcDialer configured to use the given endpoint.
func NewGrpcDialer(endpoint string, tokenProvider auth.TokenProvider, quotaProject string, logger debug.ContextLogger, useInsecure bool, timeout time.Duration, userAgent string) *GrpcDialer {
	return &GrpcDialer{
		endpoint:      endpoint,
		tokenProvider: tokenProvider,
		logger:        logger,
		useInsecure:   useInsecure,
		timeout:       timeout,
		quotaProject:  quotaProject,
		userAgent:     userAgent,
	}
}

// GrpcDialer is a Dialer that connects to the SqlDataService via gRPC.
type GrpcDialer struct {
	endpoint      string
	tokenProvider auth.TokenProvider
	logger        debug.ContextLogger
	useInsecure   bool
	timeout       time.Duration

	// sqlDataClientMu synchronizes access to the data conn and the client.
	sqlDataClientMu sync.RWMutex
	sqlDataConn     *grpc.ClientConn
	sqlDataClient   sqldatagrpcpb.SqlDataServiceClient
	quotaProject    string
	userAgent       string
}

// Close closes the underlying gRPC client connection.
func (d *GrpcDialer) Close() error {
	d.sqlDataClientMu.RLock()
	c := d.sqlDataConn
	d.sqlDataClientMu.RUnlock()
	if c == nil {
		// client is already initialized. Return early.
		return nil
	}

	// Client is nil. Initialize the client.
	d.sqlDataClientMu.Lock()
	defer d.sqlDataClientMu.Unlock()
	return d.sqlDataConn.Close()
}

func (d *GrpcDialer) initSQLDataClient() (sqldatagrpcpb.SqlDataServiceClient, error) {
	d.sqlDataClientMu.RLock()
	c := d.sqlDataClient
	d.sqlDataClientMu.RUnlock()
	if c != nil {
		// client is already initialized. Return early.
		return c, nil
	}

	// Client is nil. Initialize the client.
	d.sqlDataClientMu.Lock()
	defer d.sqlDataClientMu.Unlock()

	if c := d.sqlDataClient; c != nil {
		// Client was initialized between releasing the read lock and acquiring
		// the write lock.
		return c, nil
	}

	opts := []grpc.DialOption{
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(100 * 1024 * 1024)),
		grpc.WithDefaultCallOptions(grpc.MaxCallSendMsgSize(100 * 1024 * 1024)),
	}
	if d.userAgent != "" {
		opts = append(opts, grpc.WithUserAgent(d.userAgent))
	}
	if d.useInsecure {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		ts := oauth2adapt.TokenSourceFromTokenProvider(d.tokenProvider)
		opts = append(opts,
			grpc.WithTransportCredentials(grpccreds.NewClientTLSFromCert(nil, "")),
			grpc.WithPerRPCCredentials(oauth.TokenSource{TokenSource: ts}),
		)
	}

	sqlDataConn, err := grpc.NewClient(d.endpoint, opts...)
	if err != nil {
		return nil, err
	}
	c = sqldatagrpcpb.NewSqlDataServiceClient(sqlDataConn)
	d.sqlDataConn = sqlDataConn
	d.sqlDataClient = c
	return c, nil
}

// ConnectSQLDataService connects to the SqlDataService for the given connection name.
func (d *GrpcDialer) ConnectSQLDataService(ctx context.Context, cn instance.ConnName) (conn net.Conn, err error) {
	// ctx is the context with a 30 second timeout, which would allow the stream to connect.
	// it should not be used as the context for the grpc stream call, which will run for
	// more than the initial connection timeout.
	// We're leaving the ctx argument in for future use.

	c, err := d.initSQLDataClient()
	if err != nil {
		return nil, err
	}
	streamCtx, streamCancel := context.WithCancel(context.Background())

	// Linked context will cancel the stream only while Dial is in progress.
	dialDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			streamCancel()
		case <-dialDone:
		}
	}()
	defer close(dialDone)

	// routing_parameters: [ { field: "instance_id" }, { field: "location_id" } ]
	instanceID := fmt.Sprintf("projects/%s/instances/%s", cn.Project(), cn.Name())
	streamCtx = metadata.AppendToOutgoingContext(streamCtx,
		"x-goog-request-params", fmt.Sprintf("instance_id=%s&location_id=locations/%s", instanceID, cn.Region()))

	// If quota-project cli flag is set, add the request header.
	if d.quotaProject != "" {
		streamCtx = metadata.AppendToOutgoingContext(streamCtx, "x-goog-user-project", d.quotaProject)
	}

	var timeoutCancel context.CancelFunc
	if d.timeout > 0 {
		d.logger.Debugf(streamCtx, "Setting timeout: %v", d.timeout)
		streamCtx, timeoutCancel = context.WithTimeout(streamCtx, d.timeout)
	}

	stream, err := c.StreamSqlData(streamCtx)
	if err != nil {
		if timeoutCancel != nil {
			timeoutCancel()
		}
		streamCancel()
		return nil, err
	}
	err = stream.Send(sqldatapb.StreamSqlDataRequest_builder{
		StartSession: sqldatapb.StartSession_builder{
			LocationId: proto.String(fmt.Sprintf("locations/%s", cn.Region())),
			InstanceId: proto.String(instanceID),
		}.Build(),
	}.Build())
	if err != nil {
		if timeoutCancel != nil {
			timeoutCancel()
		}
		streamCancel()
		return nil, err
	}
	d.logger.Debugf(streamCtx, "Dialing via SqlDataService: %v", cn.Name())
	return &streamConn{
		stream:        stream,
		timeoutCancel: timeoutCancel,
		streamCancel:  streamCancel,
		connName:      cn,
		locationID:    fmt.Sprintf("locations/%s", cn.Region()),
		logger:        d.logger,
	}, nil
}

// streamConn wraps the gRPC stream to implement net.Conn
type streamConn struct {
	stream        sqldatagrpcpb.SqlDataService_StreamSqlDataClient
	timeoutCancel context.CancelFunc
	streamCancel  context.CancelFunc
	connName      instance.ConnName
	locationID    string
	readBuf       []byte
	readOffset    int
	logger        debug.ContextLogger
}

func (c *streamConn) Read(b []byte) (n int, err error) {
	if c.readOffset < len(c.readBuf) {
		n = copy(b, c.readBuf[c.readOffset:])
		c.readOffset += n
		return n, nil
	}
	// During read, ignore unknown messages. This will allow old clients to work correctly
	// even if new clients introduce new messages.
	msg, err := c.stream.Recv()
	if err != nil {
		// This could be io.EOF or a gRPC error
		return 0, err
	}

	if !msg.HasData() {
		// Ignore unknown messages, treat them as a 0 length read to avoid unnecessary blocking.
		// The caller will retry the read if appropriate.
		c.logger.Debugf(context.Background(), "Received unknown message %v", msg)
		return 0, nil
	}
	c.readBuf = msg.GetData().GetData()
	c.readOffset = 0
	n = copy(b, c.readBuf)
	c.readOffset = n
	return n, nil
}

func (c *streamConn) Write(b []byte) (n int, err error) {
	err = c.stream.Send(sqldatapb.StreamSqlDataRequest_builder{
		Data: sqldatapb.DataPacket_builder{
			Data: b,
		}.Build(),
	}.Build())
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *streamConn) Close() error {
	if c.timeoutCancel != nil {
		c.timeoutCancel()
	}
	if c.streamCancel != nil {
		c.streamCancel()
	}
	return c.stream.CloseSend()
}

func (c *streamConn) LocalAddr() net.Addr {
	return localAddr{}
}

func (c *streamConn) RemoteAddr() net.Addr {
	return remoteAddr{}
}

func (c *streamConn) SetDeadline(_ time.Time) error {
	return nil
}

func (c *streamConn) SetReadDeadline(_ time.Time) error {
	return nil
}

func (c *streamConn) SetWriteDeadline(_ time.Time) error {
	return nil
}

type localAddr struct{}

func (la localAddr) Network() string { return "grpc" }
func (la localAddr) String() string  { return "local" }

type remoteAddr struct{}

func (ra remoteAddr) Network() string { return "grpc" }
func (ra remoteAddr) String() string  { return "remote" }
