// Copyright 2024 Google LLC
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
	"context"
	"sync"
	"testing"
	"time"

	"cloud.google.com/go/auth"
	"cloud.google.com/go/cloudsqlconn/instance"
	"cloud.google.com/go/cloudsqlconn/internal/mock"
)

func TestLazyRefreshCacheConnectionInfo(t *testing.T) {
	cn, _ := instance.ParseConnName("my-project:my-region:my-instance")
	inst := mock.NewFakeCSQLInstance(cn.Project(), cn.Region(), cn.Name())
	client, cleanup, err := mock.NewSQLAdminService(
		context.Background(),
		mock.InstanceGetSuccess(inst, 1),
		mock.CreateEphemeralSuccess(inst, 1),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := cleanup(); err != nil {
			t.Fatalf("%v", err)
		}
	}()
	c := NewLazyRefreshCache(
		testInstanceConnName(), nullLogger{}, client,
		RSAKey, 30*time.Second, nil, "", false,
	)

	ci, err := c.ConnectionInfo(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if ci.ConnectionName != cn {
		t.Fatalf("want = %v, got = %v", cn, ci.ConnectionName)
	}
	// Request connection info again to ensure it uses the cache and doesn't
	// send another API call.
	_, err = c.ConnectionInfo(context.Background())
	if err != nil {
		t.Fatal(err)
	}
}

func TestLazyRefreshCacheForceRefresh(t *testing.T) {
	cn, _ := instance.ParseConnName("my-project:my-region:my-instance")
	inst := mock.NewFakeCSQLInstance(cn.Project(), cn.Region(), cn.Name())
	client, cleanup, err := mock.NewSQLAdminService(
		context.Background(),
		mock.InstanceGetSuccess(inst, 2),
		mock.CreateEphemeralSuccess(inst, 2),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := cleanup(); err != nil {
			t.Fatalf("%v", err)
		}
	}()
	c := NewLazyRefreshCache(
		testInstanceConnName(), nullLogger{}, client,
		RSAKey, 30*time.Second, nil, "", false,
	)

	_, err = c.ConnectionInfo(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	c.ForceRefresh()

	_, err = c.ConnectionInfo(context.Background())
	if err != nil {
		t.Fatal(err)
	}
}

// spyTokenProvider is a non-threadsafe spy for tracking token provider usage
type spyTokenProvider struct {
	mu    sync.Mutex
	count int
}

func (s *spyTokenProvider) Token(context.Context) (*auth.Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.count++
	return &auth.Token{}, nil
}

func (s *spyTokenProvider) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.count
}

func TestLazyRefreshCacheUpdateRefresh(t *testing.T) {
	cn, _ := instance.ParseConnName("my-project:my-region:my-instance")
	inst := mock.NewFakeCSQLInstance(cn.Project(), cn.Region(), cn.Name())
	client, cleanup, err := mock.NewSQLAdminService(
		context.Background(),
		mock.InstanceGetSuccess(inst, 2),
		mock.CreateEphemeralSuccess(inst, 2),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := cleanup(); err != nil {
			t.Fatalf("%v", err)
		}
	}()

	spy := &spyTokenProvider{}
	c := NewLazyRefreshCache(
		testInstanceConnName(), nullLogger{}, client,
		RSAKey, 30*time.Second, spy, "", false, // disable IAM AuthN at first
	)

	_, err = c.ConnectionInfo(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if got := spy.callCount(); got != 0 {
		t.Fatal("auth.TokenProvider was called, but should not have been")
	}

	c.UpdateRefresh(ptr(true))

	_, err = c.ConnectionInfo(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// Q: Why should the token provider be called twice?
	// A: Because the refresh code retrieves a token first (1 call) and then
	//    refreshes it (1 call) for a total of 2 calls.
	if got, want := spy.callCount(), 2; got != want {
		t.Fatalf(
			"auth.TokenProvider call count, got = %v, want = %v",
			got, want,
		)
	}
}

func ptr(val bool) *bool {
	return &val
}
