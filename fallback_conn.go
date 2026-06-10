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
	"bytes"
	"net"
	"sync"
	"time"
)

// fallbackConn delegates to a GRPC stream connection, but if it fails with a specific error
// it will retry connecting to a
type fallbackConn struct {
	// The state for handling fallback due to an error on the first read
	mu            sync.RWMutex
	firstReadDone bool
	closed        bool
	conn          net.Conn
	writebuf      *bytes.Buffer

	// connFallback generates
	isFallbackError func(error) bool
	connectFallback func() (net.Conn, error)
}

func (c *fallbackConn) Read(b []byte) (int, error) {
	// If the connection is closed, immediately return ErrClosed
	c.mu.RLock()
	if c.closed {
		c.mu.RUnlock()
		return 0, net.ErrClosed
	}

	// The first read completed successfully. do a normal read.
	if c.firstReadDone {
		defer c.mu.RUnlock()
		return c.conn.Read(b)
	}

	// This is probably the first read, acquire the write lock until this method returns.
	c.mu.RUnlock()
	c.mu.Lock()

	// recheck closed
	if c.closed {
		// Closed, return error.
		c.mu.Unlock()
		return 0, net.ErrClosed
	}

	// recheck first read
	if c.firstReadDone {
		// Not the first read, release state lock, then read and return the result.
		conn := c.conn
		c.mu.Unlock()
		return conn.Read(b)
	}

	// Do the first read.
	defer c.mu.Unlock()
	n, err := c.conn.Read(b)
	c.firstReadDone = true

	// If there is no error, or the error should not create a fallback connection,
	// return the result of c.conn.Read()
	if err == nil || !c.isFallbackError(err) {
		return n, err
	}

	// Read failed and this should dial the fallback connection.
	var newConn net.Conn
	newConn, err = c.connectFallback()
	if err != nil {
		return 0, err
	}

	// Fallback connection succeeded. Send write buffer.
	for c.writebuf != nil && c.writebuf.Len() > 0 {
		_, err := c.writebuf.WriteTo(newConn)
		if err != nil {
			_ = newConn.Close()
			return 0, err
		}
	}

	// new conn is ready for reads.
	c.conn = newConn
	return c.conn.Read(b)

}

func (c *fallbackConn) Write(b []byte) (int, error) {
	// Acquire the state read lock.
	c.mu.RLock()
	// Check closed
	if c.closed {
		c.mu.RUnlock()
		return 0, net.ErrClosed
	}
	// Check if first read is done
	if c.firstReadDone {
		c.mu.RUnlock()
		return c.conn.Write(b)
	}

	// This is probably before the first read. Acquire the state write lock.
	c.mu.RUnlock()
	c.mu.Lock()

	// recheck closed
	if c.closed {
		c.mu.Unlock()
		return 0, net.ErrClosed
	}
	// recheck firstReadDone
	if c.firstReadDone {
		conn := c.conn
		// This is after the first read. Release the write lock before calling conn.Write().
		c.mu.Unlock()
		return conn.Write(b)
	}

	// Write to the conn
	n, err := c.conn.Write(b)
	if err != nil {
		c.mu.Unlock()
		return n, err
	}

	// Add bytes written to the write buffer
	if c.writebuf == nil {
		c.writebuf = bytes.NewBuffer(nil)
	}
	c.writebuf.Write(b[:n])

	// Return the result
	c.mu.Unlock()
	return n, err
}

func (c *fallbackConn) Close() error {
	c.mu.Lock()
	c.closed = true
	conn := c.conn
	c.mu.Unlock()
	return conn.Close()
}

func (c *fallbackConn) LocalAddr() net.Addr {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.conn.LocalAddr()
}

func (c *fallbackConn) RemoteAddr() net.Addr {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.conn.RemoteAddr()
}

func (c *fallbackConn) SetDeadline(t time.Time) error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.conn.SetDeadline(t)
}

func (c *fallbackConn) SetReadDeadline(t time.Time) error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.conn.SetReadDeadline(t)
}

func (c *fallbackConn) SetWriteDeadline(t time.Time) error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.conn.SetWriteDeadline(t)
}
