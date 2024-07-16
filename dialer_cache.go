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
	"sync"

	"cloud.google.com/go/cloudsqlconn/debug"
	"cloud.google.com/go/cloudsqlconn/instance"
)

// dialerCache manages a thread-safe map of ConnName to monitoredCache. This
// provides thread safe operations to atomically get or add an entry, scan all
// entries and update or remove some of them, and to find entries using the
// domain name or ConnName.
type dialerCache struct {
	mu     sync.RWMutex
	cache  map[instance.ConnName]*monitoredCache
	logger debug.ContextLogger
}

// newDialerCache creates and initializes an instance of the dialer cache
func newDialerCache(logger debug.ContextLogger) *dialerCache {
	return &dialerCache{
		cache:  make(map[instance.ConnName]*monitoredCache),
		logger: logger,
	}
}

// findByDomainName returns the entry that matches the domain name.
// dn - the domain name
// returns:
//
//	instance.ConnName the name of the matching instance
//	monitoredCache the cached item
//	bool true when there is a result.
//
// This method is thread safe. This method is not re-entrant.
func (d *dialerCache) findByDomainName(dn string) (instance.ConnName, *monitoredCache, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	for cn, c := range d.cache {
		if cn.DomainName() == dn {
			return cn, c, true
		}
	}
	return instance.ConnName{}, nil, false
}

// get returns the instance matching the cn.
//
// This method is not re-entrant.
func (d *dialerCache) get(cn instance.ConnName) (*monitoredCache, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	c, ok := d.cache[cn]
	return c, ok
}

// getOrAdd returns the cache entry, creating it if necessary. This will also
// take care to remove entries with the same domain name.
//
// cn - the connection name to getOrAdd
// f - the function to use to create a new cache, may return an error
//
// returns:
//
//	monitoredCache - the cached entry
//	monitoredCache - the evicted entry if the cache already contained another
//	entry with the same domain name.
//	error - an error if the cache entry could not be created.
//
// This method is not re-entrant.
func (d *dialerCache) getOrAdd(cn instance.ConnName, f func() (*monitoredCache, error)) (*monitoredCache, *monitoredCache, error) {
	var oldC *monitoredCache

	d.mu.RLock()
	c, ok := d.cache[cn]
	d.mu.RUnlock()
	if ok && !c.isClosed() {
		return c, oldC, nil
	}

	// If not found, acquire write lock.
	d.mu.Lock()
	defer d.mu.Unlock()

	// Look up in the map by CN again
	c, ok = d.cache[cn]
	if ok {
		if !c.isClosed() {
			return c, nil, nil
		}
		// c is closed, therefore remove it from the cache.
		oldC = c
		delete(d.cache, cn)
	}

	// Try to get an instance with the same domain name but different instance
	// Remove this instance from the cache, it will be replaced.
	if cn.HasDomainName() {
		for oldCn, oc := range d.cache {
			if oldCn.DomainName() == cn.DomainName() && oldCn != cn {
				oldC = oc
				delete(d.cache, oldCn)
				break
			}
		}
	}

	// Create the new instance and put it in the cache
	c, err := f()
	if err != nil {
		return nil, oldC, err
	}

	// Instance created successfully. Return it.
	d.cache[cn] = c
	return c, oldC, nil
}

// remove removes the cached item, returning the monitoredCache or nil
// if no entry was found for cn.
//
// This method is not re-entrant.
func (d *dialerCache) remove(cn instance.ConnName) *monitoredCache {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Look up in the map by CN again
	c, ok := d.cache[cn]
	if ok {
		delete(d.cache, cn)
	}

	return c
}

// clear empties the cache, returning the contents of the cache.
//
// This method is not re-entrant.
func (d *dialerCache) clear() map[instance.ConnName]*monitoredCache {
	d.mu.Lock()
	defer d.mu.Unlock()
	old := d.cache
	d.cache = make(map[instance.ConnName]*monitoredCache)
	return old
}
