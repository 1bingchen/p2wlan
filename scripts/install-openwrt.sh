#!/bin/sh
set -eu

VERSION=${P2WLAN_VERSION:-}
REPO=${P2WLAN_REPO:-yhan-sun/p2wlan}
DRY_RUN=0
usage() {
  echo 'Usage: sh install-openwrt.sh --version vX.Y.Z [--dry-run]'
}
while [ "$#" -gt 0 ]; do
  case "$1" in
    --version)
      [ "$#" -ge 2 ] || { usage >&2; exit 1; }
      VERSION=$2
      shift 2
      ;;
    --version=*) VERSION=${1#*=}; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 1 ;;
  esac
done
case "$VERSION" in
  v?*) ;;
  *) echo 'An explicit release tag vX.Y.Z is required.' >&2; exit 1 ;;
esac
case "$VERSION" in
  *[!A-Za-z0-9._-]*) echo 'Invalid release tag.' >&2; exit 1 ;;
esac
case "$REPO" in
  */*) ;;
  *) echo 'Invalid repository.' >&2; exit 1 ;;
esac
case "$REPO" in
  *[!A-Za-z0-9._/-]*|*/*/*|/*|*/) echo 'Invalid repository.' >&2; exit 1 ;;
esac
[ -r /etc/openwrt_release ] || { echo 'This installer requires OpenWrt.' >&2; exit 1; }
release=$(sed -n "s/^DISTRIB_RELEASE='\([^']*\)'$/\1/p" /etc/openwrt_release)
arch=$(sed -n "s/^DISTRIB_ARCH='\([^']*\)'$/\1/p" /etc/openwrt_release)
case "$release" in
  24.10.*) series=24.10; extension=ipk; manager=opkg ;;
  25.12.*) series=25.12; extension=apk; manager=apk ;;
  *) echo "Unsupported OpenWrt release: $release (supported: 24.10, 25.12)." >&2; exit 1 ;;
esac
case "$arch" in
  x86_64|aarch64_generic|aarch64_cortex-a53|aarch64_cortex-a72|aarch64_cortex-a76) ;;
  *) echo "Unsupported OpenWrt package architecture: $arch." >&2; exit 1 ;;
esac
asset="p2wlan-openwrt-$series-$arch.$extension"
base="https://github.com/$REPO/releases/download/$VERSION"
echo "OpenWrt $release ($arch): $asset from $VERSION"
[ "$DRY_RUN" -eq 0 ] || exit 0
[ "$(id -u)" -eq 0 ] || { echo 'Run as root on the router.' >&2; exit 1; }
for tool in "$manager" jsonfilter sha256sum mktemp; do
  command -v "$tool" >/dev/null || { echo "Required command missing: $tool" >&2; exit 1; }
done
download() {
  if command -v curl >/dev/null; then
    curl -fL --retry 2 --connect-timeout 20 --max-time 180 "$1" -o "$2"
  elif command -v wget >/dev/null; then
    wget -q -T 60 -O "$2" "$1"
  else
    echo 'Install curl or wget with HTTPS support first.' >&2
    exit 1
  fi
}
work=$(mktemp -d /tmp/p2wlan-install.XXXXXX)
trap 'rm -rf "$work"' EXIT HUP INT TERM
download "$base/RELEASE-MANIFEST.json" "$work/manifest.json"
[ "$(jsonfilter -i "$work/manifest.json" -e '@.schema_version')" = 3 ] &&
  [ "$(jsonfilter -i "$work/manifest.json" -e '@.tag')" = "$VERSION" ] || {
    echo 'Release manifest schema/tag mismatch.' >&2; exit 1;
  }
expected=$(jsonfilter -i "$work/manifest.json" -e "@.files[\"$asset\"].sha256")
case "$expected" in
  ''|*[!0-9a-f]*) echo 'Missing/invalid package checksum in release manifest.' >&2; exit 1 ;;
esac
[ "${#expected}" -eq 64 ] || { echo 'Invalid SHA-256 length.' >&2; exit 1; }
download "$base/$asset" "$work/$asset"
actual=$(sha256sum "$work/$asset")
[ "${actual%% *}" = "$expected" ] || { echo 'Package checksum mismatch; refusing installation.' >&2; exit 1; }
if [ "$manager" = apk ]; then
  apk update
  apk add --allow-untrusted "$work/$asset"
else
  opkg update
  opkg install "$work/$asset"
fi
echo 'Installed. Configure with p2wlan config set control, log in, then run p2wlan up.'
