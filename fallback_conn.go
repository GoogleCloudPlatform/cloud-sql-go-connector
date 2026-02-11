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
	conn          net.Conn
	writebuf      *bytes.Buffer

	// connFallback generates
	isFallbackError func(error) bool
	connectFallback func() (net.Conn, error)
}

func (c *fallbackConn) Read(b []byte) (int, error) {
	// If we already finished the first read, then return
	c.mu.RLock()
	if c.firstReadDone {
		defer c.mu.RUnlock()
		return c.conn.Read(b)
	}
	// This is the first read, acquire the write lock
	c.mu.RUnlock()
	c.mu.Lock()
	conn := c.conn
	firstReadDone := c.firstReadDone
	c.mu.Unlock()

	if firstReadDone {
		return conn.Read(b)
	}

	n, err := conn.Read(b)
	c.firstReadDone = true
	if err != nil && c.isFallbackError(err) {
		return c.reconnectAndRead(b)
	}
	c.mu.Lock()
	firstReadDone = true
	c.mu.Unlock()
	return n, err
}

func (c *fallbackConn) reconnectAndRead(b []byte) (int, error) {
	// This only gets called during read, so the mutex already has a write lock
	newConn, err := c.connectFallback()
	if err != nil {
		return 0, err
	}
	// Write cached write bytes
	if c.writebuf != nil && c.writebuf.Len() > 0 {
		_, err = c.writebuf.WriteTo(newConn)
		if err != nil {
			return 0, err
		}
	}
	c.mu.Lock()
	c.conn = newConn
	c.mu.Unlock()

	return newConn.Read(b)
}

func (c *fallbackConn) Write(b []byte) (int, error) {
	// If we already finished the first read, then return
	c.mu.RLock()
	if c.firstReadDone {
		defer c.mu.RUnlock()
		return c.conn.Write(b)
	}
	// This write is before the first read, acquire the write lock
	c.mu.RUnlock()
	c.mu.Lock()
	conn := c.conn
	firstReadDone := c.firstReadDone
	c.mu.Unlock()

	if firstReadDone {
		return conn.Write(b)
	}
	n, err := conn.Write(b)
	if err != nil {
		return n, err
	}
	// Cache bytes written to the socket

	c.mu.Lock()
	if c.writebuf == nil {
		c.writebuf = bytes.NewBuffer(make([]byte, len(b)*2))
		c.writebuf.Reset()
	}
	c.writebuf.Write(b[:n])
	c.mu.Unlock()
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

func (c *fallbackConn) SetWriteDeadline(t time.Time) error {
	return nil
}
