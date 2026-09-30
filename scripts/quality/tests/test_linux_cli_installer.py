import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
INSTALLER = ROOT / "scripts/install-linux-cli.sh"


class LinuxCLIInstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.installer = self.directory / "install.sh"
        shutil.copyfile(INSTALLER, self.installer)
        self.bin_dir = self.directory / "bin"
        self.bin_dir.mkdir()
        self.command_log = self.directory / "commands.log"
        uname = self.bin_dir / "uname"
        uname.write_text(
            '#!/bin/sh\nprintf "uname\\n" >> "$INSTALLER_TEST_LOG"\n'
            'printf "%s\\n" "$INSTALLER_TEST_ARCH"\n',
            encoding="utf-8",
        )
        uname.chmod(0o755)
        for command in ("curl", "wget", "install"):
            stub = self.bin_dir / command
            stub.write_text(
                f'#!/bin/sh\nprintf "{command}\\n" >> "$INSTALLER_TEST_LOG"\n'
                f'echo "Unexpected {command} in installer dry-run test" >&2\nexit 1\n',
                encoding="utf-8",
            )
            stub.chmod(0o755)
        self.environment = {
            key: value for key, value in os.environ.items()
            if key not in {"P2WLAN_VERSION", "P2WLAN_REPO", "P2WLAN_INSTALL_DIR"}
        }
        self.environment.update({
            "PATH": str(self.bin_dir) + os.pathsep + os.environ["PATH"],
            "INSTALLER_TEST_LOG": str(self.command_log),
            "INSTALLER_TEST_ARCH": "x86_64",
        })

    def run_installer(self, tag, source="argument", arch="x86_64", locale=None):
        self.command_log.unlink(missing_ok=True)
        environment = {**self.environment, "INSTALLER_TEST_ARCH": arch}
        if locale is not None:
            environment["LC_ALL"] = locale
        arguments = ["sh", str(self.installer), "--dry-run"]
        if source == "argument":
            arguments.extend(["--version", tag])
        elif source == "equals":
            arguments.append("--version=" + tag)
        else:
            environment["P2WLAN_VERSION"] = tag
        return subprocess.run(
            arguments, env=environment, capture_output=True, text=True, timeout=5
        )

    def test_invalid_remote_tags_fail_before_package_selection(self):
        tags = [
            "v", "main", "latest", "server-v1.2.3", "v/1.2.3",
            "v1.2.3/../../latest", "v1.2.3?download=1", "v1.2.3#fragment",
            "v1.2.3 trailing", "v1.2.3\n", "v1.2.3é",
        ]
        for source in ("argument", "equals", "environment"):
            for tag in tags:
                with self.subTest(source=source, tag=tag):
                    result = self.run_installer(tag, source)
                    self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                    self.assertIn("--version must look like vX.Y.Z.", result.stderr)
                    self.assertEqual(result.stdout, "")
                    self.assertFalse(self.command_log.exists())

    def test_supported_tag_characters_and_architectures_remain_accepted(self):
        for source in ("argument", "equals", "environment"):
            for tag in ("v1.2.3", "v1.2.3-rc.1", "v1.2.3_preview-A", "vmain"):
                for arch, asset_arch in (("x86_64", "x64"), ("aarch64", "arm64")):
                    with self.subTest(source=source, tag=tag, arch=arch):
                        result = self.run_installer(tag, source, arch)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertIn(
                            f"/releases/download/{tag}/p2wlan-linux-{asset_arch}-cli.tar.gz",
                            result.stdout,
                        )

    def test_remote_tag_alphabet_is_ascii_in_available_locales(self):
        installed = subprocess.check_output(["locale", "-a"], text=True, timeout=5)
        locales = ["C"] + [
            name for name in installed.splitlines()
            if name.lower().replace("-", "").endswith("utf8")
            and name.lower().startswith(("en_us.", "de_de.", "tr_tr."))
        ]
        for locale in locales:
            for tag in ("v1.2.3é", "v1.2.3É", "v1.2.3İ", "v1.2.3ı"):
                with self.subTest(locale=locale, tag=tag):
                    result = self.run_installer(tag, locale=locale)
                    self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                    self.assertEqual(result.stdout, "")
                    self.assertFalse(self.command_log.exists())
            with self.subTest(locale=locale, tag="v1.2.3_preview-A"):
                result = self.run_installer("v1.2.3_preview-A", locale=locale)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_remote_version_is_rejected(self):
        result = self.run_installer("", "environment")
        self.assertEqual(result.returncode, 1)
        self.assertIn("required for a reproducible remote install", result.stderr)
        self.assertFalse(self.command_log.exists())

    def test_local_package_does_not_require_remote_version(self):
        for name in ("p2wlan", "p2wlan-daemon", "README-LINUX-CLI.txt"):
            (self.directory / name).touch()
        result = self.run_installer("", "environment")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Would install", result.stdout)
        self.assertNotIn("Would download", result.stdout)
        self.assertFalse(self.command_log.exists())


if __name__ == "__main__":
    unittest.main()
