#!/bin/bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$root"
binary=${1:-target/release/sfera-net}
output=${2:?Usage: package.sh BINARY OUTPUT}
staging=$(mktemp -d)
trap 'rm -rf "$staging"' EXIT
install -m 0755 "$binary" "$staging/sfera-net"
install -m 0755 deploy/selfhost/{install.sh,sferactl.py} "$staging"
install -m 0644 deploy/selfhost/sfera-selfhost.service "$staging"
install -m 0755 deploy/sfera-test-network.sh "$staging/network.sh"
COPYFILE_DISABLE=1 tar -czf "$output" -C "$staging" install.sh network.sh sferactl.py sfera-net sfera-selfhost.service
