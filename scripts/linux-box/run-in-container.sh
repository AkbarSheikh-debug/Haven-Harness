#!/bin/sh
# Runs a command in a copy of this repository inside a Linux container, the way the Linux box is verified on a
# machine with Docker. bubblewrap needs namespaces that Docker's default seccomp profile forbids, so the container is
# privileged: say so wherever a result from it is reported ("tested in a privileged container on kernel <uname -r>").
#
#   scripts/linux-box/run-in-container.sh [--ordinary] <command...>
#
# The repository is copied (never mounted writable), so the container cannot change it. Needs Docker.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
mode=--privileged
if [ "${1:-}" = "--ordinary" ]; then mode=; shift; fi
[ $# -gt 0 ] || { echo "usage: $0 [--ordinary] <command...>" >&2; exit 2; }
image=hn-linux-box-test
docker build -q -t "$image" "$here" >/dev/null
# A path from Git Bash on Windows must reach Docker unchanged.
case "$(uname -s)" in MINGW*|MSYS*) src=$(cd "$repo" && pwd -W); export MSYS_NO_PATHCONV=1;; *) src=$repo;; esac
exec docker run --rm $mode \
  -v "$src:/src:ro" \
  -v hn-linux-box-pnpm:/root/.local/share/pnpm \
  -v hn-linux-box-cargo:/usr/local/cargo/registry \
  -e HN_REQUIRE_BOX=1 \
  "$image" sh -c '
    set -eu
    mkdir /work && cd /src && tar --exclude=node_modules --exclude=target --exclude=.git -cf - . | tar -C /work -xf -
    cd /work
    echo "[container] kernel $(uname -r), $(bwrap --version)"
    "$@"
  ' sh "$@"
