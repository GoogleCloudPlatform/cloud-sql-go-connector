#!/usr/bin/env bash
# Script to run the Cloud SQL Go Connector Metric Prototype.

set -e

# Change directory to project root (2 levels up from cmd/metric_prototype)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "${PROJECT_ROOT}"

echo "=== Cloud SQL Go Connector Metric Prototype Runner ==="

# Check if CSQL_INSTANCE_CONNECTION_NAME is set
if [ -z "${CSQL_INSTANCE_CONNECTION_NAME}" ]; then
  echo "Error: CSQL_INSTANCE_CONNECTION_NAME environment variable is not set."
  echo ""
  echo "Usage:"
  echo "  export CSQL_INSTANCE_CONNECTION_NAME=\"<project>:<region>:<instance>\""
  echo "  ./cmd/metric_prototype/run.sh"
  echo ""
  exit 1
fi

echo "Target Instance: ${CSQL_INSTANCE_CONNECTION_NAME}"
echo "Starting prototype..."
echo ""

# Run the prototype
go run ./cmd/metric_prototype/main.go
