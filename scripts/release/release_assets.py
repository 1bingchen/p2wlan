"""Versioned public asset sets shared by candidate and published-release gates."""

import re

LEGACY_PRIMARY = {
    "p2wlan-android-arm64-release.apk": ("android", "arm64"),
    "p2wlan-ios-arm64-unsigned.ipa": ("ios", "arm64"),
    "p2wlan-linux-arm64-cli.tar.gz": ("linux-cli", "arm64"),
    "p2wlan-linux-x64-cli.tar.gz": ("linux-cli", "x64"),
    "p2wlan-linux-x64.tar.gz": ("linux", "x64"),
    "p2wlan-macos-arm64.dmg": ("macos", "arm64"),
    "p2wlan-macos-x64.dmg": ("macos", "x64"),
    "p2wlan-windows-x64-setup.exe": ("windows", "x64"),
}
CHECKSUMS = ("p2wlan-linux-arm64-cli.tar.gz.sha256", "p2wlan-linux-x64-cli.tar.gz.sha256")
LEGACY_PAYLOADS = tuple(sorted((*LEGACY_PRIMARY, *CHECKSUMS)))
OPENWRT_PRIMARY = {
    f"p2wlan-openwrt-{series}-{arch}.{extension}": (f"openwrt-{series}", arch)
    for series, extension in (("24.10", "ipk"), ("25.12", "apk"))
    for arch in ("aarch64_generic", "aarch64_cortex-a53", "aarch64_cortex-a72", "aarch64_cortex-a76", "x86_64")
}
PRIMARY = {**LEGACY_PRIMARY, **OPENWRT_PRIMARY}
PAYLOADS = tuple(sorted((*PRIMARY, *CHECKSUMS)))


def manifest_schema(tag: str) -> int:
    """A newer tag cannot hide missing OpenWrt assets by downgrading its schema."""
    match = re.fullmatch(r"v(\d+)\.(\d+)\.(\d+)(?:[-+].*)?", tag)
    if match and tuple(map(int, match.groups())) < (0, 1, 170):
        return 2
    return 3
