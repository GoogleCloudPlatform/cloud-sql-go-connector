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
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

type mockConn struct {
	net.Conn
	readFunc  func([]byte) (int, error)
	writeFunc func([]byte) (int, error)
	closeFunc func() error
}

func (m *mockConn) Read(b []byte) (int, error) {
	if m.readFunc != nil {
		return m.readFunc(b)
	}
	return 0, io.EOF
}

func (m *mockConn) Write(b []byte) (int, error) {
	if m.writeFunc != nil {
		return m.writeFunc(b)
	}
	return len(b), nil
}

func (m *mockConn) Close() error {
	if m.closeFunc != nil {
		return m.closeFunc()
	}
	return nil
}

func (m *mockConn) LocalAddr() net.Addr                { return nil }
func (m *mockConn) RemoteAddr() net.Addr               { return nil }
func (m *mockConn) SetDeadline(_ time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(_ time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(_ time.Time) error { return nil }

func TestFallbackConn_HappyPath(t *testing.T) {
	expectedData := []byte("success")
	primary := &mockConn{
		readFunc: func(b []byte) (int, error) {
			copy(b, expectedData)
			return len(expectedData), nil
		},
	}

	fb := &fallbackConn{
		conn: primary,
		isFallbackError: func(_ error) bool {
			return false
		},
	}

	buf := make([]byte, 10)
	n, err := fb.Read(buf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if n != len(expectedData) {
		t.Errorf("Read %d bytes, want %d", n, len(expectedData))
	}
	if !bytes.Equal(buf[:n], expectedData) {
		t.Errorf("Read got %q, want %q", buf[:n], expectedData)
	}

	if !fb.firstReadDone {
		t.Error("firstReadDone should be true")
	}
}

func TestFallbackConn_BasicFallback(t *testing.T) {
	fallbackErr := errors.New("fallback needed")
	primary := &mockConn{
		readFunc: func(_ []byte) (int, error) {
			return 0, fallbackErr
		},
	}

	expectedData := []byte("fallback_success")
	secondary := &mockConn{
		readFunc: func(b []byte) (int, error) {
			copy(b, expectedData)
			return len(expectedData), nil
		},
	}

	fb := &fallbackConn{
		conn: primary,
		isFallbackError: func(err error) bool {
			return err == fallbackErr
		},
		connectFallback: func() (net.Conn, error) {
			return secondary, nil
		},
	}

	buf := make([]byte, 20)
	n, err := fb.Read(buf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if n != len(expectedData) {
		t.Errorf("Read %d bytes, want %d", n, len(expectedData))
	}
	if !bytes.Equal(buf[:n], expectedData) {
		t.Errorf("Read got %q, want %q", buf[:n], expectedData)
	}
}

func TestFallbackConn_WriteCachingFallback(t *testing.T) {
	fallbackErr := errors.New("fallback needed")
	primary := &mockConn{
		readFunc: func(_ []byte) (int, error) {
			return 0, fallbackErr
		},
		writeFunc: func(b []byte) (int, error) {
			return len(b), nil
		},
	}

	expectedReadData := []byte("fallback_response")
	var writtenData []byte
	secondary := &mockConn{
		readFunc: func(b []byte) (int, error) {
			copy(b, expectedReadData)
			return len(expectedReadData), nil
		},
		writeFunc: func(b []byte) (int, error) {
			writtenData = append(writtenData, b...)
			return len(b), nil
		},
	}

	fb := &fallbackConn{
		conn: primary,
		isFallbackError: func(err error) bool {
			return err == fallbackErr
		},
		connectFallback: func() (net.Conn, error) {
			return secondary, nil
		},
	}

	// Write something first
	writeData := []byte("hello")
	if _, err := fb.Write(writeData); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Now read, expecting failure on primary and switch to secondary
	buf := make([]byte, 20)
	n, err := fb.Read(buf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	// Check if data was replayed to secondary
	if !bytes.Equal(writtenData, writeData) {
		t.Errorf("Secondary received %q, want %q", writtenData, writeData)
	}

	// Check read data
	if n != len(expectedReadData) {
		t.Errorf("Read %d bytes, want %d", n, len(expectedReadData))
	}
	if !bytes.Equal(buf[:n], expectedReadData) {
		t.Errorf("Read got %q, want %q", buf[:n], expectedReadData)
	}
}

func TestFallbackConn_NonFallbackError(t *testing.T) {
	nonFallbackErr := errors.New("fatal error")
	primary := &mockConn{
		readFunc: func(_ []byte) (int, error) {
			return 0, nonFallbackErr
		},
	}

	fb := &fallbackConn{
		conn: primary,
		isFallbackError: func(_ error) bool {
			// This error should NOT trigger fallback
			return false
		},
		connectFallback: func() (net.Conn, error) {
			t.Fatal("connectFallback should not be called")
			return nil, nil
		},
	}

	buf := make([]byte, 10)
	_, err := fb.Read(buf)
	if err == nil {
		t.Fatal("Read expected error, got nil")
	}
	if err != nonFallbackErr {
		t.Errorf("Read got error %v, want %v", err, nonFallbackErr)
	}

	// firstReadDone should be true even on error
	if !fb.firstReadDone {
		t.Error("firstReadDone should be true after Read error")
	}
}
