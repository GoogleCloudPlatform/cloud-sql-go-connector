# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# update_go.sh updates all GitHub Action workflows to use the provided Go
# version.

usage() {
    echo "Missing Go version."
    echo "usage: .github/update_go.sh <version>"
    echo "  Example:"
    echo "    .github/update_go.sh 1.18"
}

if [ -z "$1" ]
  then
    usage
fi

# Replace all usages of "go-version: x.xx" with the provided version.
grep -lr "go-version: \"" .github/workflows | xargs \
    sed -i "s/go-version: \".*\"/go-version: \"$1\"/g"

# Replace the matrix of Go versions with the last two versions and the provided
# version.
grep -lr "go-version: \[" .github | xargs \
    sed -i "s/\[\(.*\), \(.*\), \(.*\)\]/\[\2, \3, $1\]/"
