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
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"

	"cloud.google.com/go/cloudsqlconn/debug"
	"cloud.google.com/go/cloudsqlconn/errtype"
	"cloud.google.com/go/cloudsqlconn/internal/mdx"
	"google.golang.org/protobuf/proto"
)

const maxMessageSize = 16384

var signature = []byte("CSQLMDEX")
var mdxSignatureLength = len(signature)
var mdxHeaderLength = mdxSignatureLength + 4

// MDXConn holds the ClientProtocolTLS connection and additional connection metadata.
type MDXConn struct {
	// The connection, embedded for easy access to the implementation
	net.Conn
	req        *mdx.MetadataExchangeRequest
	res        *mdx.MetadataExchangeResponse
	r          *bufio.Reader
	w          io.Writer
	logger     debug.ContextLogger
	cn         string
	firstRead  bool
	firstWrite bool
}

// NewMDXConn Creates a new *MDXConn and initializes it.
func NewMDXConn(tlsConn net.Conn, cn string, req *mdx.MetadataExchangeRequest, logger debug.ContextLogger) *MDXConn {
	return &MDXConn{
		Conn:   tlsConn,
		r:      bufio.NewReader(tlsConn),
		w:      tlsConn,
		logger: logger,
		cn:     cn,
		req:    req,
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
func (c *MDXConn) Read(b []byte) (int, error) {
	if !c.firstRead {
		res, mdxErr := c.readMDX()
		if mdxErr != nil {
			return 0, mdxErr
		}
		c.res = res
		c.firstRead = true
	}
	return c.r.Read(b)
}

// Read implements io.Reader interface, delegating to the internal buffered reader.
func (c *MDXConn) Write(b []byte) (int, error) {
	if !c.firstWrite {
		if c.req != nil {
			mdxErr := c.writeMDX(c.req)
			if mdxErr != nil {
				return 0, mdxErr
			}
		}
		c.firstWrite = true
	}
	return c.w.Write(b)
}

// readMDX reads the MDX request message from the socket.
func (c *MDXConn) readMDX() (*mdx.MetadataExchangeResponse, error) {
	// ctx only used for debug logging
	ctx := context.Background()
	c.logger.Debugf(ctx, "[%v] Reading MDX response...", c.cn)

	// Progressively peek from 1 to 8 bytes from the socket. If at any point it does not match, there's an i/o
	// error, or if the read times out, then return.
	for l := 1; l <= mdxSignatureLength; l++ {
		peekBuf, err := c.r.Peek(l)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			c.logger.Debugf(ctx, "MDX Read Timeout Error: error peeking first %d bytes for the MDX request: %v", l, err)
			// Ignore IO timeout error. Assume that if no MDX was sent within 250ms following the
			// CLIENT_PROTOCOL_TLS handshake, then there will be no MDX request, and the database client is waiting for
			// the server to respond.
			return nil, errtype.NewDialError(fmt.Sprintf("MDX Read Timeout Error: error peeking first %d bytes for the MDX request: %v", l, err), c.cn, err)
		} else if err != nil {
			c.logger.Debugf(ctx, "MDX Read Error: error peeking first %d bytes for the MDX request: %v", l, err)
			return nil, errtype.NewDialError(fmt.Sprintf("MDX Read Error: error peeking first %d bytes for the MDX request", l), c.cn, err)
		}

		if !bytes.Equal(peekBuf, signature[:len(peekBuf)]) {
			c.logger.Debugf(ctx, "MDX Read: No MDX response, first %d bytes do not match MDX signature. %v", l)
			return nil, nil
		}
	}

	// Received a MDX signature, will read the response.
	// Read the 12 byte mdx header from the stream
	mdxHeaderBytes := make([]byte, mdxHeaderLength)
	_, err := io.ReadFull(c.r, mdxHeaderBytes)

	if errors.Is(err, os.ErrDeadlineExceeded) {
		return nil, errtype.NewDialError("MDX Read Timeout: read response header", c.cn, err)
	} else if err != nil {
		return nil, errtype.NewDialError("MDX Read Error: read response header", c.cn, err)
	}

	// Get the MDX message length from the MDX header
	msgLen := binary.BigEndian.Uint32(mdxHeaderBytes[mdxSignatureLength:mdxHeaderLength])
	if msgLen > maxMessageSize {
		return nil, errtype.NewDialError(fmt.Sprintf("MDX Read Format: Response too long, %d bytes", msgLen), c.cn, err)
	}

	// Read the MDX message
	mdxBytes := make([]byte, msgLen)
	_, err = io.ReadFull(c.r, mdxBytes)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return nil, errtype.NewDialError("MDX Read Timeout: read message", c.cn, err)
	} else if err != nil {
		return nil, errtype.NewDialError("MDX Read Error: read message", c.cn, err)
	}

	// Unmarshal the protobuf request
	c.res = &mdx.MetadataExchangeResponse{}
	err = proto.Unmarshal(mdxBytes, c.res)
	if err != nil {
		return nil, errtype.NewDialError("proto.Unmarshal: error unmarshalling the MDX response: %v", c.cn, err)
	}
	c.logger.Debugf(ctx, "[%v] MDX response received successfully.", c.cn)
	return c.res, nil
}

// IsResponseOk returns true if a response was received and ResponseStatusCode == OK.
func (c *MDXConn) IsResponseOk() bool {
	return c.res.ResponseStatusCode != nil &&
		*c.res.ResponseStatusCode == mdx.MetadataExchangeResponse_OK
}

// GetErrorMessage returns the ErrorMessage in the MDX Response.
func (c *MDXConn) GetErrorMessage() string {
	if c.res.ErrorMessage != nil {
		return *c.res.ErrorMessage
	}
	return ""
}

// writeMDX writes the MDX response back to the socket.
func (c *MDXConn) writeMDX(req *mdx.MetadataExchangeRequest) error {
	// ctx only used for debug logging
	ctx := context.Background()
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
