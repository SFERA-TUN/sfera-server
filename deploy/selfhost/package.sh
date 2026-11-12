#!/bin/bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$root"
binary=${1:-target/release/sfera-net}
output=${2:?Usage: package.sh BINARY OUTPUT}
version=${3:-unversioned}
if [[ $version != unversioned && ! $version =~ ^server-v(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$ ]]; then
  echo "Invalid stable release tag" >&2; exit 1
fi
staging=$(mktemp -d)
trap 'rm -rf "$staging"' EXIT
install -m 0755 "$binary" "$staging/sfera-net"
install -m 0755 deploy/selfhost/{install.sh,sferactl.py,upgrade.py} "$staging"
install -m 0644 deploy/selfhost/sfera-selfhost.service "$staging"
install -m 0755 deploy/sfera-test-network.sh "$staging/network.sh"
printf '%s\n' "$version" > "$staging/server-version"
COPYFILE_DISABLE=1 tar -czf "$output" -C "$staging" install.sh network.sh sferactl.py upgrade.py server-version sfera-net sfera-selfhost.service
