// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cloudsqlconn

import (
	"context"
	"errors"
	"testing"

	"cloud.google.com/go/cloudsqlconn/instance"
)

type testLog struct {
	t *testing.T
}

func (l *testLog) Debugf(_ context.Context, f string, args ...interface{}) {
	l.t.Logf(f, args...)
}

func TestDialerCache_Get_CreatesInstance(t *testing.T) {
	cache := newDialerCache(&testLog{t: t})
	var wantOpenConns uint64 = 10
	wantCn, _ := instance.ParseConnName("myproject:region:instance")

	c, _, err := cache.getOrAdd(wantCn, func() (*monitoredCache, error) {
		return &monitoredCache{openConnsCount: &wantOpenConns}, nil
	})

	if err != nil {
		t.Error("Got error, want no error", err)
	}
	if *c.openConnsCount != wantOpenConns {
		t.Fatal("Got wrong cache instance")
	}
}

func TestDialerCache_Get_UsesExistingInstance(t *testing.T) {
	cache := newDialerCache(&testLog{t: t})
	var wantOpenConns uint64 = 10
	var dontWantOpenConns uint64 = 20
	wantCn, _ := instance.ParseConnName("myproject:region:instance")

	c, _, err := cache.getOrAdd(wantCn, func() (*monitoredCache, error) {
		return &monitoredCache{openConnsCount: &wantOpenConns}, nil
	})

	if err != nil {
		t.Error("Got error, want no error", err)
	}
	if *c.openConnsCount != wantOpenConns {
		t.Fatal("Got wrong cache instance")
	}

	c2, _, err := cache.getOrAdd(wantCn, func() (*monitoredCache, error) {
		return &monitoredCache{openConnsCount: &dontWantOpenConns}, nil
	})
	if err != nil {
		t.Error("Got error, want no error", err)
	}
	if *c2.openConnsCount != wantOpenConns {
		t.Fatal("Got wrong value for cache")
	}

}

func TestDialerCache_Get_ReplacesClosedInstance(t *testing.T) {
	cache := newDialerCache(&testLog{t: t})
	var wantOpenConns uint64 = 10
	var wantOpenConns2 uint64 = 20
	wantCn, _ := instance.ParseConnNameWithDomainName("project:region:instance", "d1.example.com")

	// First, put  d1.example.com = project:region:instance
	c, _, err := cache.getOrAdd(wantCn, func() (*monitoredCache, error) {
		return &monitoredCache{openConnsCount: &wantOpenConns}, nil
	})
	if err != nil {
		t.Error("Got error, want no error", err)
	}
	if *c.openConnsCount != wantOpenConns {
		t.Fatal("Got wrong cache instance")
	}

	// Close the instance.
	c.closed = true

	// Attempt to get the instance again after it closed. This will create
	// a new cache entry.
	c2, oldC, err := cache.getOrAdd(wantCn, func() (*monitoredCache, error) {
		return &monitoredCache{openConnsCount: &wantOpenConns2}, nil
	})
	if err != nil {
		t.Error("Got error, want no error", err)
	}
	if *oldC.openConnsCount != wantOpenConns {
		t.Fatal("Got wrong cache instance")
	}
	if *c2.openConnsCount != wantOpenConns2 {
		t.Fatal("Got wrong value for cache")
	}
	if len(cache.cache) != 1 {
		t.Fatal("Got wrong number of cache entries: want 1, got ", len(cache.cache))
	}

}

func TestDialerCache_Get_ErrorOnInstanceCreate(t *testing.T) {
	cache := newDialerCache(&testLog{t: t})
	wantCn, _ := instance.ParseConnName("myproject:region:instance")

	_, _, err := cache.getOrAdd(wantCn, func() (*monitoredCache, error) {
		return nil, errors.New("error")
	})

	if err == nil {
		t.Error("Got nil error, want error", err)
	}
}

func TestDialerCache_Get_ReplaceInstanceWithSameDomain(t *testing.T) {
	cache := newDialerCache(&testLog{t: t})
	var wantOpenConns uint64 = 10
	var wantOpenConns2 uint64 = 20
	wantCn, _ := instance.ParseConnNameWithDomainName("project:region:instance", "d1.example.com")
	wantCn2, _ := instance.ParseConnNameWithDomainName("new-project:region:instance2", "d1.example.com")

	// First, put  d1.example.com = project:region:instance
	c, _, err := cache.getOrAdd(wantCn, func() (*monitoredCache, error) {
		return &monitoredCache{openConnsCount: &wantOpenConns}, nil
	})
	if err != nil {
		t.Error("Got error, want no error", err)
	}
	if *c.openConnsCount != wantOpenConns {
		t.Fatal("Got wrong cache instance")
	}

	// Then replace it by domain name with d1.example.com =
	// new-project:region:instance2
	c2, oldC, err := cache.getOrAdd(wantCn2, func() (*monitoredCache, error) {
		return &monitoredCache{openConnsCount: &wantOpenConns2}, nil
	})
	if err != nil {
		t.Error("Got error, want no error", err)
	}
	if *oldC.openConnsCount != wantOpenConns {
		t.Fatal("Got wrong cache instance")
	}
	if *c2.openConnsCount != wantOpenConns2 {
		t.Fatal("Got wrong value for cache")
	}
	if len(cache.cache) != 1 {
		t.Fatal("Got wrong number of cache entries: want 1, got ", len(cache.cache))
	}

}

func TestDialerCache_Get_ReplaceInstanceErrorWithSameDomain(t *testing.T) {
	cache := newDialerCache(&testLog{t: t})
	var wantOpenConns uint64 = 10
	wantCn, _ := instance.ParseConnNameWithDomainName("project:region:instance", "d1.example.com")
	wantCn2, _ := instance.ParseConnNameWithDomainName("new-project:region:instance2", "d1.example.com")

	// First, put  d1.example.com = project:region:instance
	c, _, err := cache.getOrAdd(wantCn, func() (*monitoredCache, error) {
		return &monitoredCache{openConnsCount: &wantOpenConns}, nil
	})
	if err != nil {
		t.Error("Got error, want no error", err)
	}
	if *c.openConnsCount != wantOpenConns {
		t.Fatal("Got wrong cache instance")
	}

	// Then replace it by domain name with d1.example.com =
	// new-project:region:instance2
	_, oldC, err := cache.getOrAdd(wantCn2, func() (*monitoredCache, error) {
		return &monitoredCache{}, errors.New("error")
	})
	if err == nil {
		t.Error("Got error, want no error", err)
	}
	if *oldC.openConnsCount != wantOpenConns {
		t.Fatal("Got wrong old instance")
	}
	if len(cache.cache) != 0 {
		t.Fatal("Got wrong number of cache entries: want 0, got ", len(cache.cache))
	}

}

func TestDialerCache_FindByDomainName_ReturnsValue(t *testing.T) {
	cache := newDialerCache(&testLog{t: t})
	var wantOpenConns uint64 = 10
	wantCn, _ := instance.ParseConnNameWithDomainName("project:region:instance", "d1.example.com")
	// Add the cache entry
	cache.getOrAdd(wantCn, func() (*monitoredCache, error) {
		return &monitoredCache{openConnsCount: &wantOpenConns}, nil
	})

	cn, _, ok := cache.findByDomainName("d1.example.com")
	if !ok {
		t.Fatal("didnt' get d1.example.com")
	}
	if cn != wantCn {
		t.Fatal("got", cn, "want", wantCn)
	}
	if _, _, ok := cache.findByDomainName("nope.example.com"); ok {
		t.Fatal("bad result")
	}
}

func TestDialerCache_Remove_CreatesInstance(t *testing.T) {
	cache := newDialerCache(&testLog{t: t})
	var wantOpenConns uint64 = 10
	wantCn, _ := instance.ParseConnName("myproject:region:instance")

	cache.getOrAdd(wantCn, func() (*monitoredCache, error) {
		return &monitoredCache{openConnsCount: &wantOpenConns}, nil
	})
	removedC := cache.remove(wantCn)

	if *removedC.openConnsCount != wantOpenConns {
		t.Fatal("Got wrong cache instance")
	}
	if len(cache.cache) != 0 {
		t.Fatal("Got wrong number of cache entries: want 0, got ", len(cache.cache))
	}

}

func TestDialerCache_Clear(t *testing.T) {
	cache := newDialerCache(&testLog{t: t})
	var wantOpenConns uint64 = 10
	var wantOpenConns2 uint64 = 20
	wantCn, _ := instance.ParseConnNameWithDomainName("project:region:instance", "d1.example.com")
	wantCn2, _ := instance.ParseConnNameWithDomainName("project:region:instance2", "d2.example.com")

	// Add the cache entry
	cache.getOrAdd(wantCn, func() (*monitoredCache, error) {
		return &monitoredCache{openConnsCount: &wantOpenConns}, nil
	})
	cache.getOrAdd(wantCn2, func() (*monitoredCache, error) {
		return &monitoredCache{openConnsCount: &wantOpenConns2}, nil
	})

	old := cache.clear()

	if _, ok := old[wantCn]; !ok {
		t.Fatal("didnt' get d1.example.com")
	}
	if _, ok := old[wantCn2]; !ok {
		t.Fatal("didnt' get d2.example.com")
	}

	if len(cache.cache) != 0 {
		t.Fatal("Got wrong number of cache entries: want 0, got ", len(cache.cache))
	}
}
