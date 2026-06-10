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
	firstReadOnce sync.Once
	firstReadDone bool
	conn          net.Conn
	writebuf      *bytes.Buffer

	// connFallback generates
	isFallbackError func(error) bool
	connectFallback func() (net.Conn, error)
}

func (c *fallbackConn) Read(b []byte) (int, error) {
	var ranOnce bool
	var firstN int
	var firstErr error

	c.firstReadOnce.Do(func() {
		ranOnce = true

		c.mu.RLock()
		conn := c.conn
		c.mu.RUnlock()

		n, err := conn.Read(b)
		if err != nil && c.isFallbackError(err) {
			// Trigger fallback
			var newConn net.Conn
			newConn, err = c.connectFallback()
			if err != nil {
				c.mu.Lock()
				c.firstReadDone = true
				c.mu.Unlock()
				firstErr = err
				return
			}

			// Get and write cached bytes
			c.mu.Lock()
			var writeData []byte
			if c.writebuf != nil {
				writeData = c.writebuf.Bytes()
			}
			c.mu.Unlock()

			if len(writeData) > 0 {
				_, err = newConn.Write(writeData)
				if err != nil {
					newConn.Close()
					c.mu.Lock()
					c.firstReadDone = true
					c.mu.Unlock()
					firstErr = err
					return
				}
			}

			c.mu.Lock()
			c.conn = newConn
			c.firstReadDone = true
			c.mu.Unlock()

			firstN, firstErr = newConn.Read(b)
			return
		}

		c.mu.Lock()
		c.firstReadDone = true
		c.mu.Unlock()
		firstN, firstErr = n, err
	})

	if ranOnce {
		return firstN, firstErr
	}

	c.mu.RLock()
	conn := c.conn
	c.mu.RUnlock()
	return conn.Read(b)
}

func (c *fallbackConn) Write(b []byte) (int, error) {
	c.mu.RLock()
	done := c.firstReadDone
	c.mu.RUnlock()

	if done {
		c.mu.RLock()
		conn := c.conn
		c.mu.RUnlock()
		return conn.Write(b)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	// Re-check under write lock
	if c.firstReadDone {
		return c.conn.Write(b)
	}

	n, err := c.conn.Write(b)
	if err != nil {
		return n, err
	}
	if c.writebuf == nil {
		c.writebuf = bytes.NewBuffer(nil)
	}
	c.writebuf.Write(b[:n])
	return n, err
}

func (c *fallbackConn) Close() error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.conn.Close()
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

func (c *fallbackConn) SetWriteDeadline(_ time.Time) error {
	return nil
}
