#!/usr/bin/env bash
# Download the base QCOW2 cloud image the profile is scanned against.
#
# Defaults to openSUSE Leap 15.6 (the community sibling of SLES 15: same SLE 15
# codebase, open repos, no registration required), which keeps CI self-contained.
# The image ships cloud-init, which the LXD launch step uses to inject the Kitchen
# SSH user and key.
#
# For a genuine SLES 15 target, set SLES_IMAGE_URL to an SCC-registered / mirrored
# SLES qcow2 and provide SCC_REGCODE so the repos resolve. Note Leap reports itself
# as openSUSE, so controls keyed on vendor / os-release read differently than on
# real SLES.
#
# Optional env:
#   SLES_IMAGE_URL  -- full URL to a .qcow2 (default: openSUSE Leap 15.6 Minimal-VM)
# Optional args:
#   $1 -- output path (default: sles-image.qcow2)

set -euo pipefail

DEFAULT_URL="https://download.opensuse.org/distribution/leap/15.6/appliances/openSUSE-Leap-15.6-Minimal-VM.x86_64-Cloud.qcow2"
IMAGE_URL="${SLES_IMAGE_URL:-$DEFAULT_URL}"
OUTPUT_FILE="${1:-sles-image.qcow2}"

echo "Downloading SLES image from: $IMAGE_URL"
curl -fL --retry 3 --retry-delay 5 -o "$OUTPUT_FILE" "$IMAGE_URL"

# Sanity check: make sure we actually got a QCOW2 and not an HTML error page.
if ! qemu-img info "$OUTPUT_FILE" >/dev/null 2>&1; then
  echo "Downloaded file is not a valid QCOW2 image. Check SLES_IMAGE_URL." >&2
  exit 1
fi
echo "Saved SLES image to $OUTPUT_FILE"
