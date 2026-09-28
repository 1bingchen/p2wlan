"""Exercise the exact filesystem transaction embedded in the released manager."""
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]


class SupportLogStorageTests(unittest.TestCase):
    def setUp(self):
        source = (ROOT / 'scripts/p2wlan-server').read_text()
        embedded = source.split("<<'PY_SUPPORT_LOG_STORAGE'\n", 1)[1].split('\nPY_SUPPORT_LOG_STORAGE\n', 1)[0]
        self.module = {'__name__': 'support_storage_test'}
        exec(compile(embedded, str(ROOT / 'scripts/p2wlan-server'), 'exec'), self.module)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.config = self.root / 'config'
        self.config.mkdir(mode=0o700)
        self.data = self.root / 'data'
        self.data.mkdir(mode=0o750)
        self.env = self.config / 'control.env'
        self.original = b'JWT_SECRET=test-only-unchanged\nDB_PATH=/existing/database.db\n'
        self.env.write_bytes(self.original)
        self.env.chmod(0o600)
        self.error = self.module['StorageError']

    def maintain(self, action='prepare'):
        return self.module['maintain_storage'](action, str(self.config), str(self.data), os.geteuid(), os.getegid())

    def test_missing_path_is_appended_once_without_changing_existing_bytes_or_mode(self):
        self.env.write_bytes(self.original.rstrip(b'\n'))
        before = self.env.stat()
        self.assertEqual(self.maintain(), 'managed_path_ready')
        content = self.env.read_bytes()
        self.assertEqual(content, self.original + f'LOG_UPLOAD_DIR="{self.data}/log-uploads"\n'.encode())
        self.assertEqual(self.maintain(), 'managed_path_ready')
        self.assertEqual(self.env.read_bytes(), content)
        self.assertEqual((self.env.stat().st_ino, stat.S_IMODE(self.env.stat().st_mode)), (before.st_ino, 0o600))
        self.assertEqual(stat.S_IMODE((self.data / 'log-uploads').stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(self.data.stat().st_mode), 0o750)

    def test_nonempty_custom_path_is_preserved_without_creating_or_chmodding_it(self):
        custom = self.root / 'custom storage'
        custom.mkdir(mode=0o750)
        content = self.original + f'LOG_UPLOAD_DIR="{custom}"\n'.encode()
        self.env.write_bytes(content)
        self.assertEqual(self.maintain(), 'custom_path_preserved')
        self.assertEqual(self.env.read_bytes(), content)
        self.assertEqual(stat.S_IMODE(custom.stat().st_mode), 0o750)
        self.assertFalse((self.data / 'log-uploads').exists())

    def test_empty_last_assignment_is_filled_and_existing_log_content_is_untouched(self):
        self.env.write_bytes(self.original + b'LOG_UPLOAD_DIR=/old/custom\nLOG_UPLOAD_DIR=""\n')
        leaf = self.data / 'log-uploads'
        leaf.mkdir(mode=0o755)
        old = leaf / 'retained.json.gz'
        old.write_bytes(b'retained private support content')
        old.chmod(0o640)
        self.maintain()
        self.assertEqual(old.read_bytes(), b'retained private support content')
        self.assertEqual(stat.S_IMODE(old.stat().st_mode), 0o640)
        self.assertEqual(self.module['configured_path'](self.env.read_bytes()), str(leaf))

    def test_last_nonempty_assignment_prevents_default_migration(self):
        content = self.original + b'LOG_UPLOAD_DIR=\nLOG_UPLOAD_DIR=/custom/private\n'
        self.env.write_bytes(content)
        self.assertEqual(self.maintain(), 'custom_path_preserved')
        self.assertEqual(self.env.read_bytes(), content)
        self.assertFalse((self.data / 'log-uploads').exists())

    def test_quoted_whitespace_is_empty_as_in_the_server_environment_reader(self):
        self.env.write_bytes(self.original + b'LOG_UPLOAD_DIR="  "\n')
        self.maintain()
        self.assertEqual(self.module['configured_path'](self.env.read_bytes()), str(self.data / 'log-uploads'))

    def test_other_multiline_or_continued_values_cannot_override_a_custom_path(self):
        custom = self.root / 'custom-private'
        custom.mkdir(mode=0o750)
        retained = custom / 'retained.json.gz'
        retained.write_bytes(b'unchanged-support-data')
        for other in (
            b"NOTE='header\nLOG_UPLOAD_DIR=\nfooter'\n",
            b'NOTE="header\nLOG_UPLOAD_DIR=\nfooter"\n',
            b'NOTE=header\\\nLOG_UPLOAD_DIR=\n',
            b'NOTE="header\\\nLOG_UPLOAD_DIR=\nfooter"\n',
            b'# comment\\\nLOG_UPLOAD_DIR=\n',
            b'; comment\\\nLOG_UPLOAD_DIR=\n',
        ):
            with self.subTest(other=other):
                content = self.original + f'LOG_UPLOAD_DIR={custom}\n'.encode() + other
                self.env.write_bytes(content)
                for action in ('prepare', 'check'):
                    with self.assertRaisesRegex(self.error, 'unsupported_environment_syntax'):
                        self.maintain(action)
                self.assertEqual(self.env.read_bytes(), content)
                self.assertFalse((self.data / 'log-uploads').exists())
                self.assertEqual(stat.S_IMODE(custom.stat().st_mode), 0o750)
                self.assertEqual(retained.read_bytes(), b'unchanged-support-data')

    def test_multiline_other_value_is_rejected_even_when_upload_setting_is_missing(self):
        content = self.original + b"NOTE='header\nLOG_UPLOAD_DIR=\nfooter'\n"
        self.env.write_bytes(content)
        with self.assertRaisesRegex(self.error, 'unsupported_environment_syntax'):
            self.maintain()
        self.assertEqual(self.env.read_bytes(), content)
        self.assertFalse((self.data / 'log-uploads').exists())

    def test_single_line_generator_json_and_quoted_values_remain_supported(self):
        content = (self.original + b'# Comment\n; Other comment\n'
                   b'RELAY_CATALOG_JSON=[{"region":"selfhost","endpoint":"tls://relay.example.test:18081"}]\n'
                   b"NOTE='single line LOG_UPLOAD_DIR= is not an assignment'\n"
                   b'OTHER="single line with \\"escaped quotes\\""\n')
        self.env.write_bytes(content)
        self.maintain()
        self.assertTrue(self.env.read_bytes().startswith(content))
        self.assertEqual(self.module['configured_path'](self.env.read_bytes()), str(self.data / 'log-uploads'))

    def test_symlink_directory_cannot_be_taken_over(self):
        outside = self.root / 'outside'
        outside.mkdir(mode=0o755)
        (self.data / 'log-uploads').symlink_to(outside, target_is_directory=True)
        with self.assertRaises(OSError):
            self.maintain()
        self.assertEqual(stat.S_IMODE(outside.stat().st_mode), 0o755)
        self.assertEqual(self.env.read_bytes(), self.original)

    def test_symlink_ancestor_is_rejected_before_directory_or_configuration_changes(self):
        alias = self.root / 'data-alias'
        alias.symlink_to(self.data, target_is_directory=True)
        with self.assertRaises(OSError):
            self.module['maintain_storage']('prepare', str(self.config), str(alias), os.geteuid(), os.getegid())
        self.assertFalse((self.data / 'log-uploads').exists())
        self.assertEqual(self.env.read_bytes(), self.original)

    def test_linked_configuration_is_rejected_without_modifying_target(self):
        outside = self.root / 'outside.env'
        self.env.rename(outside)
        self.env.symlink_to(outside)
        with self.assertRaises(OSError):
            self.maintain()
        self.env.unlink()
        os.link(outside, self.env)
        with self.assertRaisesRegex(self.error, 'unsafe_configuration_file'):
            self.maintain()
        self.assertEqual(outside.read_bytes(), self.original)
        self.assertFalse((self.data / 'log-uploads').exists())

    def test_foreign_leaf_owner_is_rejected_before_chown_or_chmod(self):
        leaf = self.data / 'log-uploads'
        leaf.mkdir(mode=0o750)
        original_fstat = os.fstat
        inode = leaf.stat().st_ino

        def foreign_stat(fd):
            info = original_fstat(fd)
            if info.st_ino == inode:
                return SimpleNamespace(st_uid=os.geteuid() + 1)
            return info

        with mock.patch('os.fstat', side_effect=foreign_stat), mock.patch('os.fchown') as chown, mock.patch('os.fchmod') as chmod:
            with self.assertRaisesRegex(self.error, 'foreign_storage_owner'):
                self.maintain()
            chown.assert_not_called()
            chmod.assert_not_called()
        self.assertEqual(self.env.read_bytes(), self.original)
        self.assertEqual(stat.S_IMODE(leaf.stat().st_mode), 0o750)

    def test_configuration_lock_conflict_does_not_modify_storage(self):
        import fcntl
        with self.env.open('rb') as held:
            fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):
                self.maintain()
        self.assertEqual(self.env.read_bytes(), self.original)
        self.assertFalse((self.data / 'log-uploads').exists())

    def test_configuration_replacement_during_directory_prepare_is_not_overwritten(self):
        original_prepare = self.module['managed_directory']

        def replace_configuration(*args):
            original_prepare(*args)
            self.env.unlink()
            self.env.write_bytes(b'JWT_SECRET=new-owner\n')
            self.env.chmod(0o600)

        with mock.patch.dict(self.module, managed_directory=replace_configuration):
            with self.assertRaisesRegex(self.error, 'configuration_changed'):
                self.maintain()
        self.assertEqual(self.env.read_bytes(), b'JWT_SECRET=new-owner\n')

    def test_doctor_rejects_missing_configuration_without_creating_default(self):
        with self.assertRaisesRegex(self.error, 'configuration_missing'):
            self.maintain('check')
        self.assertFalse((self.data / 'log-uploads').exists())

    def test_doctor_rejects_relative_or_missing_custom_path_without_repair(self):
        self.env.write_bytes(self.original + b'LOG_UPLOAD_DIR=relative/path\n')
        with self.assertRaisesRegex(self.error, 'absolute_path_required'):
            self.maintain('check')
        missing = self.root / 'missing-custom'
        self.env.write_bytes(self.original + f'LOG_UPLOAD_DIR={missing}\n'.encode())
        with self.assertRaises(FileNotFoundError):
            self.maintain('check')
        self.assertFalse(missing.exists())

    def test_doctor_rejects_read_only_mount_before_any_credential_change(self):
        self.maintain()
        with mock.patch('os.fstatvfs', return_value=SimpleNamespace(f_flag=os.ST_RDONLY)), mock.patch('os.setuid') as setuid:
            with self.assertRaisesRegex(self.error, 'storage_read_only'):
                self.maintain('check')
            setuid.assert_not_called()

    @unittest.skipIf(os.geteuid() == 0, 'ordinary CI user is required for the real access denial')
    def test_doctor_detects_unwritable_private_directory_as_service_identity(self):
        self.maintain()
        leaf = self.data / 'log-uploads'
        leaf.chmod(0o500)
        with self.assertRaisesRegex(self.error, 'storage_not_writable'):
            self.maintain('check')
        self.assertEqual(stat.S_IMODE(leaf.stat().st_mode), 0o500)

    def test_update_prepares_storage_before_any_current_link_activation(self):
        manager = (ROOT / 'scripts/p2wlan-server').read_text()
        archive = manager.split('archive_install() {', 1)[1].split('\nstatus_server()', 1)[0]
        self.assertLess(archive.index('prepare_managed_support_storage'), archive.index('ln -sfn'))
        deploy = (ROOT / 'scripts/deploy-server.sh').read_text()
        self.assertIn('p2wlan-server update --archive "$archive"', deploy)


if __name__ == '__main__':
    unittest.main()
