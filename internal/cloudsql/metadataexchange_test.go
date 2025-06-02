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

func newFakeConn(input []byte) *fakeConn {
	return &fakeConn{
		r: bytes.NewReader(input),
		w: &bytes.Buffer{},
	}
}

func TestNewMDXConn(t *testing.T) {
	fakeConn := newFakeConn([]byte{})
	logger := &testLogger{t: t}
	cn := "my-instance"
	mdxConn := NewMDXConn(fakeConn, cn, logger)

	if mdxConn.Conn != fakeConn {
		t.Errorf("expected Conn to be the fake connection")
	}
	if mdxConn.r == nil {
		t.Errorf("expected buffered reader to be initialized")
	}
	if mdxConn.logger != logger {
		t.Errorf("expected logger to be set")
	}
	if mdxConn.cn != cn {
		t.Errorf("expected common name to be set")
	}
}

func TestMDXConnRead(t *testing.T) {
	input := []byte("hello world")
	fakeConn := newFakeConn(input)
	mdxConn := NewMDXConn(fakeConn, "", &testLogger{t: t})

	buf := make([]byte, len(input))
	n, err := mdxConn.Read(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != len(input) {
		t.Fatalf("expected to read %d bytes, but got %d", len(input), n)
	}
	if !bytes.Equal(buf, input) {
		t.Fatalf("expected to read %q, but got %q", input, buf)
	}
}

func TestReadMDX(t *testing.T) {
	logger := &testLogger{t: t}
	cn := "my-instance"
	ctx := context.Background()

	t.Run("no MDX response", func(t *testing.T) {
		fakeConn := newFakeConn([]byte("not mdx"))
		mdxConn := NewMDXConn(fakeConn, cn, logger)
		err := mdxConn.ReadMDX(ctx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if mdxConn.HasMDXResponse() {
			t.Fatal("expected no mdx response")
		}
	})

	t.Run("valid MDX response", func(t *testing.T) {
		res := &mdx.MetadataExchangeResponse{
			ResponseStatusCode: ptr(mdx.MetadataExchangeResponse_OK),
		}
		resBytes, err := proto.Marshal(res)
		if err != nil {
			t.Fatalf("failed to marshal proto: %v", err)
		}
		msg := make([]byte, len(resBytes)+mdxHeaderLength)
		copy(msg[:mdxSignatureLength], signature)
		binary.BigEndian.PutUint32(msg[mdxSignatureLength:mdxHeaderLength], uint32(len(resBytes)))
		copy(msg[mdxHeaderLength:], resBytes)

		fakeConn := newFakeConn(msg)
		mdxConn := NewMDXConn(fakeConn, cn, logger)
		err = mdxConn.ReadMDX(ctx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !mdxConn.HasMDXResponse() {
			t.Fatal("expected mdx response")
		}
		if *mdxConn.GetMDXResponse().ResponseStatusCode != mdx.MetadataExchangeResponse_OK {
			t.Fatalf("expected server version %q, but got %q", mdx.MetadataExchangeResponse_OK, mdxConn.GetMDXResponse().ResponseStatusCode)
		}
	})
}

func TestWriteMDX(t *testing.T) {
	logger := &testLogger{t: t}
	cn := "my-instance"
	ctx := context.Background()

	req := &mdx.MetadataExchangeRequest{
		ClientProtocolType: ptr(mdx.MetadataExchangeRequest_TCP),
	}

	fakeConn := newFakeConn(nil)
	mdxConn := NewMDXConn(fakeConn, cn, logger)
	err := mdxConn.WriteMDX(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify the written data
	written := fakeConn.w.Bytes()
	if !bytes.HasPrefix(written, signature) {
		t.Fatalf("expected signature prefix, but got %q", written)
	}

	reqBytes, err := proto.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal proto: %v", err)
	}
	expectedLen := uint32(len(reqBytes))
	actualLen := binary.BigEndian.Uint32(written[8:12])
	if actualLen != expectedLen {
		t.Fatalf("expected length %d, but got %d", expectedLen, actualLen)
	}

	if !bytes.HasSuffix(written, reqBytes) {
		t.Fatalf("expected request bytes suffix, but got %q", written)
	}
}
