package cloudsql

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"time"

	"cloud.google.com/go/cloudsqlconn/debug"
	"cloud.google.com/go/cloudsqlconn/errtype"
	"cloud.google.com/go/cloudsqlconn/internal/mdx"
	"github.com/golang/protobuf/proto"
)

// MDXConn holds the TLS connection and additional connection metadata.
type MDXConn struct {
	// The connection, embedded for easy access to the implementation
	net.Conn
	res    *mdx.MetadataExchangeResponse
	r      *bufio.Reader
	logger debug.ContextLogger
	cn     string
}

// Creates a new *MDXConn and initializes it.
func NewMDXConn(tlsConn net.Conn, cn string, logger debug.ContextLogger) *MDXConn {
	return &MDXConn{
		Conn:   tlsConn,
		r:      bufio.NewReader(tlsConn),
		logger: logger,
		cn:     cn,
	}
}

// HasMDXResponse returns true if the request has an MDX Request
func (c *MDXConn) HasMDXResponse() bool {
	return c.res != nil
}

// GetMDXResponse returns the mdx request or nil if none was received.
func (c *MDXConn) GetMDXResponse() *mdx.MetadataExchangeResponse {
	return c.res
}

// Read implements io.Reader interface, delegating to the internal buffered reader.
func (c *MDXConn) Read(b []byte) (n int, err error) {
	return c.r.Read(b)
}

// isMDXSignature returns true when the first 8 bytes are "CSQLMDEX".
func isMDXSignature(buf []byte) bool {
	return len(buf) >= 8 &&
		buf[0] == 'C' && buf[1] == 'S' && buf[2] == 'Q' && buf[3] == 'L' &&
		buf[4] == 'M' && buf[5] == 'D' && buf[6] == 'E' && buf[7] == 'X'
}

// Read the MDX request message from the socket.
func (c *MDXConn) ReadMDX(ctx context.Context) error {
	c.logger.Debugf(ctx, "[%v] Reading MDX response...", c.cn)

	// Set a deadline of 500 ms to peek for the header protocol.
	c.Conn.SetDeadline(time.Now().Add(time.Millisecond * 500))
	peekBuf, err := c.r.Peek(12)
	c.Conn.SetDeadline(time.Time{})

	if err != nil {
		if err == os.ErrDeadlineExceeded {
			c.logger.Debugf(ctx, "[%v] No MDX response received within 500ms.", c.cn)
			// Ignore IO timeout error. Assume that if no MDX was sent within 2 seconds following the
			// TLS handshake, then there will be no MDX request, and the database client is waiting for
			// the server to respond.
			return nil
		}
		c.logger.Debugf(ctx, "[%v] c.r.Peek: error reading the MDX response: %v", c.cn, err)
		return errtype.NewDialError("c.r.Peek: error reading the MDX response: %v", c.cn, err)
	}
	// Check if the protocol header CSQLMDEX is present
	if !isMDXSignature(peekBuf) {
		c.logger.Debugf(ctx, "[%v] No MDX response received.", c.cn)
		return nil
	}
	// Read the length of the MetadataRequest serialized protobuf data.
	l := binary.BigEndian.Uint32(peekBuf[8:])

	// Read the entire MDX message, including the 12 byte header from the stream
	mdxBytes := make([]byte, l+12)
	c.Conn.SetDeadline(time.Now().Add(time.Millisecond * 500))
	_, err = io.ReadFull(c.r, mdxBytes)
	c.Conn.SetDeadline(time.Time{})
	if err != nil {
		c.logger.Debugf(ctx, "[%v] c.r.Read: error reading the MDX response: %v", err)
		return errtype.NewDialError("c.r.Read: error reading the MDX response: %v", c.cn, err)
	}

	// Unmarshal the protobuf request
	c.res = &mdx.MetadataExchangeResponse{}
	err = proto.Unmarshal(mdxBytes[12:], c.res)
	if err != nil {
		c.logger.Debugf(ctx, "[%v] proto.Unmarshal: error unmarshalling the MDX response: %v", c.cn, err)
		return errtype.NewDialError("proto.Unmarshal: error unmarshalling the MDX response: %v", c.cn, err)
	}
	c.logger.Debugf(ctx, "[%v] MDX response received successfully.", c.cn)
	return nil
}

// WriteMDX writes the MDX response back to the socket.
func (c *MDXConn) WriteMDX(ctx context.Context, req *mdx.MetadataExchangeRequest) error {
	c.logger.Debugf(ctx, "[%v] Writing MDX request, protocol:%v...", c.cn, req.ClientProtocolType)

	resBytes, err := proto.Marshal(req)
	if err != nil {
		c.logger.Debugf(ctx, "[%v] proto.Marshal: error marshalling the MDX request: %v", c.cn, err)
		return errtype.NewDialError("proto.Marshal: error marshalling the MDX request: %v", c.cn, err)
	}
	sig := make([]byte, 12)
	sig[0] = 'C'
	sig[1] = 'S'
	sig[2] = 'Q'
	sig[3] = 'L'
	sig[4] = 'M'
	sig[5] = 'D'
	sig[6] = 'E'
	sig[7] = 'X'
	binary.BigEndian.PutUint32(sig[8:], uint32(len(resBytes)))
	_, err = c.Conn.Write(sig)
	if err != nil {
		c.logger.Debugf(ctx, "[%v] c.Conn.Write: error writing the MDX request: %v", c.cn, err)
		return errtype.NewDialError("c.Conn.Write: error writing the MDX request: %v", c.cn, err)
	}
	_, err = c.Conn.Write(resBytes)
	if err != nil {
		c.logger.Debugf(ctx, "[%v] c.Conn.Write: error writing the MDX request: %v", c.cn, err)
		return errtype.NewDialError("c.Conn.Write: error writing the MDX request: %v", c.cn, err)
	}
	c.logger.Debugf(ctx, "[%v] MDX request sent successfully.", c.cn)
	return nil
}
