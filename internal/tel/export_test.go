// Copyright 2026 Google LLC
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

package tel

import (
	"log"
	"sync"
)

// SetWarnLoggerForTest redirects the once-per-process permanent-error warning
// to l and resets the once guard. It returns a function that restores the
// previous state.
func SetWarnLoggerForTest(l *log.Logger) (restore func()) {
	prevLogger, prevOnce := warnLogger, permanentErrorOnce
	warnLogger = l
	permanentErrorOnce = new(sync.Once)
	return func() {
		warnLogger = prevLogger
		permanentErrorOnce = prevOnce
	}
}

// IsPermanentExportError exposes the export error classifier for tests.
var IsPermanentExportError = isPermanentExportError

// NextBackoff and Jitter expose the backoff helpers for tests.
var (
	NextBackoff = nextBackoff
	Jitter      = jitter
)
