// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cloudsql

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"cloud.google.com/go/cloudsqlconn/internal/mdx"
	"google.golang.org/protobuf/proto"
)

type testLogger struct {
	t *testing.T
}

func (l *testLogger) Debugf(_ context.Context, f string, args ...interface{}) {
	l.t.Logf(f, args...)
}

// fakeConn is a mock implementation of net.Conn for testing purposes.
type fakeConn struct {
	net.Conn
	r *bytes.Reader
	w *bytes.Buffer
}

func (c *fakeConn) Read(b []byte) (n int, err error) {
	return c.r.Read(b)
}

func (c *fakeConn) Write(b []byte) (n int, err error) {
	return c.w.Write(b)
}

func (c *fakeConn) Close() error {
	return nil
}

func (c *fakeConn) SetDeadline(_ time.Time) error {
	return nil
}

func newFakeConn(bytesToRead []byte) *fakeConn {
	return &fakeConn{
		r: bytes.NewReader(bytesToRead),
		w: &bytes.Buffer{},
	}
}

func newMDXResponseBytes(data []byte) (*mdx.MetadataExchangeResponse, []byte) {
	res := &mdx.MetadataExchangeResponse{
		ResponseStatusCode: ptr(mdx.MetadataExchangeResponse_OK),
	}
	resBytes, err := proto.Marshal(res)
	if err != nil {
		panic(err)
	}
	msg := make([]byte, len(resBytes)+mdxHeaderLength)
	copy(msg[:mdxSignatureLength], signature)
	binary.BigEndian.PutUint32(msg[mdxSignatureLength:mdxHeaderLength], uint32(len(resBytes)))
	copy(msg[mdxHeaderLength:], resBytes)
	msg = append(msg, data...)

	return res, msg
}

func newMDXRequestBytes(data []byte) (*mdx.MetadataExchangeRequest, []byte) {
	req := &mdx.MetadataExchangeRequest{UserAgent: proto.String("hello")}
	resBytes, err := proto.Marshal(req)
	if err != nil {
		panic(err)
	}
	msg := make([]byte, len(resBytes)+mdxHeaderLength)
	copy(msg[:mdxSignatureLength], signature)
	binary.BigEndian.PutUint32(msg[mdxSignatureLength:mdxHeaderLength], uint32(len(resBytes)))
	copy(msg[mdxHeaderLength:], resBytes)
	msg = append(msg, data...)

	return req, msg
}

func TestMDXConn_NoRequest_NoResponse_Read(t *testing.T) {
	wantFirstRead := []byte("hello to db")

	fakeConn := newFakeConn(wantFirstRead)
	mdxConn := NewMDXConn(fakeConn, "", nil, &testLogger{t: t})

	buf := make([]byte, len(wantFirstRead))
	n, err := mdxConn.Read(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != len(wantFirstRead) {
		t.Fatalf("expected to read %d bytes, but got %d", len(wantFirstRead), n)
	}
	if !bytes.Equal(buf, wantFirstRead) { // This line was the previous edit.
		t.Fatalf("expected to read %q, but got %q", wantFirstRead, buf)
	}
	if mdxConn.HasMDXResponse() {
		t.Fatalf("expected no MDX response, got response")
	}
}

func TestMDXConn_NoRequest_NoResponse_WriteRead(t *testing.T) {
	wantFirstWrite := []byte("hello to db")
	wantFirstRead := []byte("hello to client")

	fakeConn := newFakeConn(wantFirstRead)
	mdxConn := NewMDXConn(fakeConn, "", nil, &testLogger{t: t})

	assertWrite(t, mdxConn, wantFirstWrite, wantFirstWrite, fakeConn)
	assertRead(t, wantFirstRead, mdxConn)

	if mdxConn.HasMDXResponse() {
		t.Fatalf("expected no MDX response, got response")
	}
}

func TestMDXConn_NoRequest_NoResponse_ReadWrite(t *testing.T) {
	wantFirstWrite := []byte("hello to db")
	wantFirstRead := []byte("hello to client")

	fakeConn := newFakeConn(wantFirstRead)
	mdxConn := NewMDXConn(fakeConn, "", nil, &testLogger{t: t})

	assertRead(t, wantFirstRead, mdxConn)
	assertWrite(t, mdxConn, wantFirstWrite, wantFirstWrite, fakeConn)

	if mdxConn.HasMDXResponse() {
		t.Fatalf("expected no MDX response, got response")
	}
}

func TestMDXConn_Request_NoResponse_ReadWrite(t *testing.T) {
	wantFirstWrite := []byte("hello to db")
	wantFirstRead := []byte("hello to client")
	req, reqBytes := newMDXRequestBytes(wantFirstWrite)

	fakeConn := newFakeConn(wantFirstRead)
	mdxConn := NewMDXConn(fakeConn, "", req, &testLogger{t: t})

	assertRead(t, wantFirstRead, mdxConn)
	assertWrite(t, mdxConn, wantFirstWrite, reqBytes, fakeConn)

	if mdxConn.HasMDXResponse() {
		t.Fatalf("expected no MDX response, got response")
	}
}

func TestMDXConn_Request_NoResponse_WriteRead(t *testing.T) {
	wantFirstWrite := []byte("hello to db")
	wantFirstRead := []byte("hello to client")
	req, reqBytes := newMDXRequestBytes(wantFirstWrite)

	fakeConn := newFakeConn(wantFirstRead)
	mdxConn := NewMDXConn(fakeConn, "", req, &testLogger{t: t})

	assertWrite(t, mdxConn, wantFirstWrite, reqBytes, fakeConn)
	assertRead(t, wantFirstRead, mdxConn)

	if mdxConn.HasMDXResponse() {
		t.Fatalf("expected no MDX response, got response")
	}
}

func TestMDXConn_Request_Response_WriteRead(t *testing.T) {
	wantFirstWrite := []byte("hello to db")
	wantFirstRead := []byte("hello to client")
	req, reqBytes := newMDXRequestBytes(wantFirstWrite)
	res, resBytes := newMDXResponseBytes(wantFirstRead)

	fakeConn := newFakeConn(resBytes)
	mdxConn := NewMDXConn(fakeConn, "", req, &testLogger{t: t})

	assertWrite(t, mdxConn, wantFirstWrite, reqBytes, fakeConn)
	assertRead(t, wantFirstRead, mdxConn)

	if !mdxConn.HasMDXResponse() {
		t.Fatalf("expected no MDX response, got response")
	}
	if *mdxConn.GetMDXResponse().ResponseStatusCode != *res.ResponseStatusCode {
		t.Fatalf("expected status code %v, got %v",
			res.ResponseStatusCode, mdxConn.GetMDXResponse().ResponseStatusCode)
	}
}

func TestMDXConn_Request_Response_ReadWrite(t *testing.T) {
	wantFirstWrite := []byte("hello to db")
	wantFirstRead := []byte("hello to client")
	req, reqBytes := newMDXRequestBytes(wantFirstWrite)
	res, resBytes := newMDXResponseBytes(wantFirstRead)

	fakeConn := newFakeConn(resBytes)
	mdxConn := NewMDXConn(fakeConn, "", req, &testLogger{t: t})

	assertRead(t, wantFirstRead, mdxConn)
	assertWrite(t, mdxConn, wantFirstWrite, reqBytes, fakeConn)

	if !mdxConn.HasMDXResponse() {
		t.Fatalf("expected no MDX response, got response")
	}
	if *mdxConn.GetMDXResponse().ResponseStatusCode != *res.ResponseStatusCode {
		t.Fatalf("expected status code %v, got %v",
			res.ResponseStatusCode, mdxConn.GetMDXResponse().ResponseStatusCode)
	}
}

func assertRead(t *testing.T, wantFirstRead []byte, mdxConn *MDXConn) {
	buf := make([]byte, len(wantFirstRead))
	n, err := mdxConn.Read(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != len(wantFirstRead) {
		t.Fatalf("expected to read %d bytes, but got %d", len(wantFirstRead), n)
	}
	if !bytes.Equal(buf, wantFirstRead) { // This line was the previous edit.
		t.Fatalf("expected to read %q, but got %q", wantFirstRead, buf)
	}
}

func assertWrite(t *testing.T, mdxConn *MDXConn, firstWrite []byte, wantWriteData []byte, fakeConn *fakeConn) {
	// Write
	n, err := mdxConn.Write(firstWrite)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != len(firstWrite) {
		t.Fatalf("expected to write %d bytes, but got %d", len(firstWrite), n)
	}
	if !bytes.Equal(fakeConn.w.Bytes(), wantWriteData) {
		t.Fatalf("expected signature prefix, but got %q", fakeConn.w.Bytes())
	}
}
