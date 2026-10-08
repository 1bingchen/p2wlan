#!/usr/bin/env python3
"""Build baseline-CPU static musl binaries and native OpenWrt SDK packages."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]
TARGETS = json.loads(Path(__file__).with_name("targets.json").read_text())
ARM_ARCHES = ("aarch64_generic", "aarch64_cortex-a53", "aarch64_cortex-a72", "aarch64_cortex-a76")


def run(*args: str, cwd: Path = ROOT, env: dict | None = None, timeout: int = 1800) -> None:
    print("+", " ".join(map(str, args)), flush=True)
    subprocess.run(args, cwd=cwd, env=env, check=True, timeout=timeout)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download(url: str, path: Path, expected: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists() or sha256(path) != expected:
        temporary = path.with_suffix(path.suffix + ".part")
        run("curl", "-fL", "--retry", "3", "--connect-timeout", "20", "--max-time", "600",
            url, "-o", str(temporary), timeout=650)
        if sha256(temporary) != expected:
            temporary.unlink()
            raise ValueError(f"OpenWrt download checksum mismatch: {path.name}")
        temporary.replace(path)
    if sha256(path) != expected:
        raise ValueError(f"OpenWrt checksum mismatch: {path.name}")


def target_config(series: str, arch: str) -> tuple[dict, dict, str, str]:
    release = TARGETS[series]
    target = release[arch]
    stem = f"openwrt-{release['version']}-{target['target'].replace('/', '-')}"
    base = f"https://downloads.openwrt.org/releases/{release['version']}/targets/{target['target']}/"
    return release, target, stem, base


def verify_elf(path: Path, arch: str, readelf: str) -> None:
    header = subprocess.check_output([readelf, "-h", str(path)], text=True)
    expected = "AArch64" if arch == "arm64" else "Advanced Micro Devices X86-64"
    if "ELF64" not in header or expected not in header:
        raise ValueError(f"wrong ELF architecture: {path}")
    program = subprocess.check_output([readelf, "-l", str(path)], text=True)
    dynamic = subprocess.check_output([readelf, "-d", str(path)], text=True)
    if "INTERP" in program or "(NEEDED)" in dynamic:
        raise ValueError(f"OpenWrt binary is not self-contained static musl: {path}")


def build(args: argparse.Namespace) -> None:
    release, target, stem, base = target_config(args.series, args.arch)
    version = re.search(r'^version = "([^"]+)"', (ROOT / "Cargo.toml").read_text(), re.M).group(1)
    if args.tag != f"v{version}":
        raise ValueError(f"tag {args.tag} != workspace v{version}")
    source = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    if subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=all"], cwd=ROOT):
        raise ValueError("OpenWrt packages require a clean committed checkout")
    args.work_dir = args.work_dir.resolve()
    args.output = args.output.resolve()
    args.work_dir.mkdir(parents=True, exist_ok=True)
    args.output.mkdir(parents=True, exist_ok=True)
    vm_command = ("python3", "scripts/openwrt/verify_vm.py", "--series", args.series, "--arch", args.arch,
                  "--directory", str(args.output), "--work-dir", str(args.work_dir), "--source-sha", source)
    if args.stage == "verify":
        run(*vm_command, timeout=1000)
        return
    sdk_name = f"{stem.replace('openwrt-', 'openwrt-sdk-', 1)}_gcc-{release['gcc']}_musl.Linux-x86_64.tar.zst"
    archive = args.work_dir / sdk_name
    download(base + sdk_name, archive, target["sdk_sha256"])
    sdk = args.work_dir / sdk_name.removesuffix(".tar.zst")
    if not sdk.is_dir():
        run("tar", "--zstd", "-xf", str(archive), "-C", str(args.work_dir))
    cpu = "aarch64" if args.arch == "arm64" else "x86_64"
    rust_target = f"{cpu}-unknown-linux-musl"
    compilers = list(sdk.glob(f"staging_dir/toolchain-*/bin/{cpu}-openwrt-linux-musl-gcc"))
    if len(compilers) != 1:
        raise ValueError(f"expected one SDK C compiler, found {compilers}")
    compiler = compilers[0]
    readelf = str(compiler).removesuffix("gcc") + "readelf"
    env = os.environ.copy()
    env.update({
        "STAGING_DIR": str(sdk / "staging_dir"),
        f"CARGO_TARGET_{rust_target.replace('-', '_').upper()}_LINKER": str(compiler),
        f"CC_{rust_target.replace('-', '_')}": str(compiler),
        f"AR_{rust_target.replace('-', '_')}": str(compiler).removesuffix("gcc") + "ar",
        "CARGO_TARGET_DIR": str(args.work_dir / "cargo-target"),
        "RUSTFLAGS": "-C target-feature=+crt-static -C link-self-contained=yes",
        "CARGO_PROFILE_RELEASE_OPT_LEVEL": "s",
    })
    if args.stage in ("all", "compile"):
        run("cargo", "build", "--locked", "--release", "-p", "p2wlan-cli", "-p", "p2wlan-daemon",
            "--target", rust_target, env=env, timeout=2700)
    binaries = args.work_dir / "cargo-target" / rust_target / "release"
    for name in ("p2wlan", "p2wlan-daemon"):
        verify_elf(binaries / name, args.arch, readelf)
    if args.stage == "compile":
        return
    recipe = sdk / "package/p2wlan"
    shutil.rmtree(recipe, ignore_errors=True)
    shutil.copytree(ROOT / "deploy/openwrt", recipe)
    (sdk / ".config").write_text(
        "# CONFIG_ALL is not set\n# CONFIG_ALL_NONSHARED is not set\n"
        "# CONFIG_ALL_KMODS is not set\nCONFIG_PACKAGE_p2wlan=m\n"
        "# CONFIG_SIGNED_PACKAGES is not set\n")
    common = [f"P2WLAN_VERSION={version}", f"P2WLAN_BINARY_DIR={binaries}"]
    arches = ARM_ARCHES if args.arch == "arm64" else ("x86_64",)
    # STAGING_DIR is needed by the cross-GCC wrapper above. SDK make owns its
    # target/host staging paths and must not inherit that Cargo-only override.
    sdk_env = os.environ.copy()
    sdk_env.pop("STAGING_DIR", None)
    run("make", "defconfig", *common, f"P2WLAN_PACKAGE_ARCH={arches[0]}", cwd=sdk, env=sdk_env)
    resolved_config = set((sdk / ".config").read_text().splitlines())
    for option in ("ALL", "ALL_NONSHARED", "ALL_KMODS"):
        if f"# CONFIG_{option} is not set" not in resolved_config:
            raise ValueError(f"SDK unexpectedly enabled bulk package selection: {option}")
    for package_arch in arches:
        variables = [*common, f"P2WLAN_PACKAGE_ARCH={package_arch}"]
        run("make", "package/p2wlan/clean", *variables, cwd=sdk, env=sdk_env)
        # Packaging copies the verified static binaries and needs no target
        # library builds. The SDK otherwise repackages every pinned kmod via
        # the TUN dependency. Runtime DEPENDS stay in the recipe and the VM
        # installs them normally from the matching firmware's package feeds.
        run("make", "package/p2wlan/compile", "NO_DEPS=1", "V=s", "-j2", *variables, cwd=sdk, env=sdk_env)
        packages = list(sdk.glob(f"bin/packages/**/p2wlan*.{release['extension']}"))
        # SDK output names vary between IPK and APK. Reject ambiguous/stale
        # output rather than selecting a previous variant by modification time.
        if len(packages) != 1:
            raise ValueError(f"expected one freshly built package: {packages}")
        package = packages[0]
        name = f"p2wlan-openwrt-{args.series}-{package_arch}.{release['extension']}"
        output = args.output / name
        shutil.copyfile(package, output)
        package.unlink()
        verify_package_arch(output, package_arch, sdk)
        run("python3", "scripts/release/write_artifact_metadata.py", "--artifact", str(output),
            "--source-sha", source, "--tag", args.tag, "--platform", f"openwrt-{args.series}",
            "--arch", package_arch, "--identity", "musl-static-sdk-packaged")
    # Each architecture/series must boot and install its native package with
    # real dependencies on the matching OpenWrt kernel before it can ship.
    if args.stage == "all":
        run(*vm_command, timeout=1000)


def verify_package_arch(package: Path, arch: str, sdk: Path) -> None:
    if package.suffix == ".apk":
        metadata = subprocess.check_output([str(sdk / "staging_dir/host/bin/apk"), "adbdump", str(package)], text=True)
        pattern = rf"(?m)^\s*arch:\s*[\"']?{re.escape(arch)}[\"']?\s*$"
        if not re.search(pattern, metadata):
            raise ValueError(f"APK has wrong package architecture: {package.name}\n{metadata[:2000]}")
    else:
        # OpenWrt IPKs are tar containers (not Debian ar containers).
        raw = subprocess.check_output(["tar", "-xOf", str(package), "./control.tar.gz"])
        control = subprocess.check_output(["tar", "-xzO", "./control"], input=raw).decode()
        if f"Architecture: {arch}\n" not in control:
            raise ValueError(f"IPK has wrong package architecture: {package.name}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--series", choices=TARGETS, required=True)
    parser.add_argument("--arch", choices=("arm64", "x64"), required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=ROOT / "dist-release")
    parser.add_argument("--tag", required=True)
    parser.add_argument("--stage", choices=("all", "compile", "package", "verify"), default="all")
    build(parser.parse_args())


if __name__ == "__main__":
    main()
