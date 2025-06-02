package cloudsql

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"cloud.google.com/go/cloudsqlconn/debug"
	"cloud.google.com/go/cloudsqlconn/errtype"
	"cloud.google.com/go/cloudsqlconn/internal/mdx"
	"google.golang.org/protobuf/proto"
)

var signature = []byte("CSQLMDEX")
var mdxSignatureLength = len(signature)
var mdxHeaderLength = mdxSignatureLength + 4

// MDXConn holds the TLS connection and additional connection metadata.
type MDXConn struct {
	// The connection, embedded for easy access to the implementation
	net.Conn
	res    *mdx.MetadataExchangeResponse
	r      *bufio.Reader
	logger debug.ContextLogger
	cn     string
}

// NewMDXConn Creates a new *MDXConn and initializes it.
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

// ReadMDX reads the MDX request message from the socket.
func (c *MDXConn) ReadMDX(ctx context.Context) error {
	c.logger.Debugf(ctx, "[%v] Reading MDX response...", c.cn)

	// Set a deadline of 30 seconds to read the metadata exchange response
	c.Conn.SetDeadline(time.Now().Add(time.Second * 30))
	defer c.Conn.SetDeadline(time.Time{})

	// Progressively peek from 1 to 8 bytes from the socket. If at any point it does not match, there's an i/o
	// error, or if the read times out, then return.
	for l := 1; l <= mdxSignatureLength; l++ {
		peekBuf, err := c.r.Peek(l)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			c.logger.Debugf(ctx, "MDX Read Timeout Error: error peeking first %d bytes for the MDX request: %v", l, err)
			// Ignore IO timeout error. Assume that if no MDX was sent within 250ms following the
			// TLS handshake, then there will be no MDX request, and the database client is waiting for
			// the server to respond.
			return errtype.NewDialError(fmt.Sprintf("MDX Read Timeout Error: error peeking first %d bytes for the MDX request: %v", l, err), c.cn, err)
		} else if err != nil {
			c.logger.Debugf(ctx, "MDX Read Error: error peeking first %d bytes for the MDX request: %v", l, err)
			return errtype.NewDialError(fmt.Sprintf("MDX Read Error: error peeking first %d bytes for the MDX request", l), c.cn, err)
		}
		if !bytes.Equal(peekBuf, signature[:len(peekBuf)]) {
			c.logger.Debugf(ctx, "MDX Read: First %d bytes do not match MDX signature.", l)
			return nil
		}
	}

	// Received a MDX signature, will read the response.
	// Read the 12 byte mdx header from the stream
	mdxHeaderBytes := make([]byte, mdxHeaderLength)
	_, err := io.ReadFull(c.r, mdxHeaderBytes)

	if errors.Is(err, os.ErrDeadlineExceeded) {
		return errtype.NewDialError("MDX Read Timeout: read response header", c.cn, err)
	} else if err != nil {
		return errtype.NewDialError("MDX Read Error: read response header", c.cn, err)
	}

	// Get the MDX message length from the MDX header
	msgLen := binary.BigEndian.Uint32(mdxHeaderBytes[mdxSignatureLength:mdxHeaderLength])
	if msgLen > 4096 {
		return errtype.NewDialError(fmt.Sprintf("MDX Read Format: Response too long, %d bytes", msgLen), c.cn, err)
	}

	// Read the MDX message
	mdxBytes := make([]byte, msgLen)
	_, err = io.ReadFull(c.r, mdxBytes)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return errtype.NewDialError("MDX Read Timeout: read message", c.cn, err)
	} else if err != nil {
		return errtype.NewDialError("MDX Read Error: read message", c.cn, err)
	}

	// Unmarshal the protobuf request
	c.res = &mdx.MetadataExchangeResponse{}
	err = proto.Unmarshal(mdxBytes, c.res)
	if err != nil {
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
	copy(sig[0:8], signature)
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
