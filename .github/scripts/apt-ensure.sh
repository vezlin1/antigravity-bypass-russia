#!/usr/bin/env bash
# Install only the listed Debian packages the runner image does not already have.
# The hosted Ubuntu images ship most of them; `apt-get update` alone costs ~10s.
set -euo pipefail
missing=()
for package in "$@"; do
    dpkg-query -W -f='${Status}' "$package" 2>/dev/null | grep -q 'install ok installed' || missing+=("$package")
done
if ((${#missing[@]} == 0)); then
    echo "Already installed: $*"
    exit 0
fi
echo "Installing: ${missing[*]}"
sudo apt-get update -qq
sudo apt-get install -y -qq --no-install-recommends "${missing[@]}"
