#!/usr/bin/env bash
# Download a SLES 15 JeOS QCOW2 cloud image.
#
# Pulls a prebuilt SLES 15 JeOS "OpenStack-Cloud" qcow2 from SUSE's public image
# repository. That image ships cloud-init, which the LXD launch step uses to
# inject the Kitchen SSH user and key.
#
# Override SLES_IMAGE_URL to pin a different service pack / build, or to point at
# an internal mirror or an SCC-registered image.
#
# Optional env:
#   SLES_IMAGE_URL  -- full URL to a .qcow2 (default: SLE-15 JeOS OpenStack-Cloud)
# Optional args:
#   $1 -- output path (default: sles-image.qcow2)

set -euo pipefail

DEFAULT_URL="https://download.opensuse.org/repositories/SUSE:/Templates:/Images:/SLE-15/images/SLES15-JeOS.x86_64-15.0-OpenStack-Cloud-Build3.59.qcow2"
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
