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

package mock

import (
	"fmt"
	"io"

	sqldatagrpcpb "cloud.google.com/go/cloudsqlconn/internal/sqldatagrpc"
)

// FakeSQLDataServiceServer is a mock implementation of the SqlDataService gRPC server.
type FakeSQLDataServiceServer struct {
	sqldatagrpcpb.UnimplementedSqlDataServiceServer
	// OnStreamSQLData is called when a stream is established.
	// It gives the test control over the stream.
	OnStreamSQLData func(sqldatagrpcpb.SqlDataService_StreamSqlDataServer) error
}

// StreamSqlData implements the gRPC service method.
// revive:disable-next-line:var-naming
func (s *FakeSQLDataServiceServer) StreamSqlData(stream sqldatagrpcpb.SqlDataService_StreamSqlDataServer) error {
	if s.OnStreamSQLData != nil {
		return s.OnStreamSQLData(stream)
	}

	// Default behavior: Read requests and discard them until EOF.
	for {
		_, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("fake StreamSqlData recv: %w", err)
		}
	}
}
