import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import publish_results as pub


@unittest.skipUnless(shutil.which('git'), 'Git required for publication integration tests')
class Publication(unittest.TestCase):
    def test_history_snapshot_noop_and_branch_guard(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / 'repo'
            remote = Path(temp) / 'remote.git'
            root.mkdir()

            def git(*args, cwd=root):
                return subprocess.run(['git', *args], cwd=cwd, check=True,
                                      capture_output=True, text=True).stdout.strip()

            git('init', '-b', 'main')
            git('init', '--bare', str(remote))
            git('config', 'user.name', 'Test')
            git('config', 'user.email', 'test@example.invalid')
            (root / 'README.md').write_text('code retained')
            git('add', '.')
            git('commit', '-m', 'Initial')
            git('remote', 'add', 'origin', str(remote))
            git('push', '-u', 'origin', 'main')
            (root / 'proxies').mkdir()
            (root / 'proxies' / 'http.txt').write_text('1.1.1.1:80\n')
            (root / 'proxies' / 'meta.json').write_text(json.dumps({'working': {'http': 1}, 'timestamp': 'test'}))
            cfg = {'publish': {'branch': '', 'mode': 'history'}}
            with patch.object(pub, 'ROOT', root), patch.object(pub, 'load_config', return_value=cfg):
                pub.publish()
                tip = git('rev-parse', 'refs/heads/main', cwd=remote)
                self.assertEqual(git('rev-list', '--count', 'main', cwd=remote), '2')
                self.assertEqual(git('show', 'main:README.md', cwd=remote), 'code retained')
                # Simulate the next Actions checkout of the newly published commit.
                git('fetch', 'origin', 'main')
                git('reset', '--soft', 'FETCH_HEAD')
                pub.publish()
                self.assertEqual(git('rev-parse', 'main', cwd=remote), tip)
                cfg['publish'] = {'branch': 'data', 'mode': 'snapshot'}
                pub.publish()
                files = git('ls-tree', '-r', '--name-only', 'data', cwd=remote).splitlines()
                self.assertEqual(files, ['proxies/http.txt', 'proxies/meta.json'])
                self.assertEqual(git('rev-list', '--count', 'data', cwd=remote), '1')
                data_tip = git('rev-parse', 'data', cwd=remote)
                pub.publish()
                self.assertEqual(git('rev-parse', 'data', cwd=remote), data_tip)
                (root / 'proxies' / 'http.txt').write_text('1.0.0.1:80\n')
                pub.publish()
                self.assertEqual(git('rev-list', '--count', 'data', cwd=remote), '1')
                self.assertNotEqual(git('rev-parse', 'data', cwd=remote), data_tip)
                cfg['publish']['branch'] = 'main'
                with self.assertRaisesRegex(ValueError, 'separate data branch'):
                    pub.publish()
