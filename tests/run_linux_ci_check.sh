#!/usr/bin/env bash
set -euo pipefail

overlay_mount=/var/lib/containers/storage/overlay
if ! findmnt --kernel --nocanonicalize --mountpoint "$overlay_mount" --noheadings >/dev/null; then
    exec "$@"
fi

# lsof reports incomplete results when a hosted runner puts its root-only
# container storage on a separate mount. Keep real file-lock checks and
# detach only that mount from this test process's private namespace.
echo "Isolating runner container storage from lsof checks"
exec sudo -n -E /usr/bin/unshare --mount --propagation private /bin/bash -euc '
    /usr/bin/umount --lazy -- "$1"
    launch_path=$2
    shift 2
    exec /usr/sbin/runuser --user "$SUDO_USER" -- /usr/bin/env "PATH=$launch_path" "$@"
' bash "$overlay_mount" "$PATH" "$@"
