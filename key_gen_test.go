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
	"crypto/rsa"
	"errors"
	"testing"
)

func TestKeyGenerator(t *testing.T) {
	custom := &rsa.PrivateKey{}
	generated := &rsa.PrivateKey{}

	tcs := []struct {
		desc    string
		key     *rsa.PrivateKey
		lazy    bool
		genFunc func() (*rsa.PrivateKey, error)
		wantKey *rsa.PrivateKey
		// whether key generation should happen in the initializer or the call
		// to rsaKey
		wantLazy bool
	}{
		{
			desc: "by default a key is generated",
			genFunc: func() (*rsa.PrivateKey, error) {
				return generated, nil
			},
			wantKey: generated,
		},
		{
			desc: "a custom key skips the generator",
			key:  custom,
			genFunc: func() (*rsa.PrivateKey, error) {
				return nil, errors.New("generator should not be called")
			},
			wantKey: custom,
		},
		{
			desc: "lazy generates keys on first request",
			lazy: true,
			genFunc: func() (*rsa.PrivateKey, error) {
				return generated, nil
			},
			wantKey:  generated,
			wantLazy: true,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.desc, func(t *testing.T) {
			g, err := newKeyGenerator(tc.key, tc.lazy, tc.genFunc)
			if err != nil {
				t.Fatal(err)
			}
			if tc.wantLazy && g.key != nil {
				t.Fatal("want RSA key to be lazily generated, but it wasn't")
			}
			k, err := g.rsaKey()
			if err != nil {
				t.Fatal(err)
			}
			if tc.wantKey != k {
				t.Fatalf("want = %v, got = %v", tc.wantKey, k)
			}
		})
	}
}

func TestKeyGeneratorErrors(t *testing.T) {
	sentinel := errors.New("sentinel error")
	tcs := []struct {
		desc          string
		key           *rsa.PrivateKey
		lazy          bool
		genFunc       func() (*rsa.PrivateKey, error)
		wantInitError error
		wantKeyError  error
	}{
		{
			desc: "generator returns errors",
			genFunc: func() (*rsa.PrivateKey, error) {
				return nil, sentinel
			},
			wantInitError: sentinel,
			wantKeyError:  sentinel,
		},
		{
			desc: "custom keys never error",
			key:  &rsa.PrivateKey{},
			genFunc: func() (*rsa.PrivateKey, error) {
				return nil, errors.New("generator should not be called")
			},
			wantInitError: nil,
			wantKeyError:  nil,
		},
		{
			desc: "lazy generation returns errors",
			lazy: true,
			genFunc: func() (*rsa.PrivateKey, error) {
				return nil, sentinel
			},
			// initialization should succeed
			wantInitError: nil,
			// but requesting the key later should fail
			wantKeyError: sentinel,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.desc, func(t *testing.T) {
			g, err := newKeyGenerator(tc.key, tc.lazy, tc.genFunc)
			if err != tc.wantInitError {
				t.Fatal("initialization should fail, but did not")
			}
			_, err = g.rsaKey()
			if err != tc.wantKeyError {
				t.Fatal("rsaKey should fail but didn't")
			}
		})
	}
}
