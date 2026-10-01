"""Publish only proxies/ using an isolated Git index; no checkout/reset required."""
import json
import os
from pathlib import Path
import subprocess
import tempfile

from proxy_pipeline import ROOT, load_config


def git(*args, env=None, input=None, check=True):
    return subprocess.run(['git', *args], cwd=ROOT, env=env, input=input,
                          text=True, capture_output=True, check=check).stdout.strip()


def publish():
    cfg = load_config()
    default = git('branch', '--show-current')
    branch = cfg['publish']['branch'] or default
    mode = cfg['publish']['mode']
    if mode not in ('history', 'snapshot') or not branch:
        raise ValueError('Invalid publication mode or branch')
    git('check-ref-format', f'refs/heads/{branch}')
    if mode == 'snapshot' and branch == default:
        raise ValueError('Snapshot mode requires a separate data branch')
    output = ROOT / 'proxies'
    meta = json.loads((output / 'meta.json').read_text(encoding='utf-8'))
    if not sum(meta['working'].values()):
        raise ValueError('Refusing to publish empty results')
    ref = f'refs/heads/{branch}'
    remote = git('ls-remote', '--heads', 'origin', ref)
    expected = remote.split()[0] if remote else ''
    if expected:
        git('fetch', '--no-tags', 'origin', ref)
        # Use the exact fetched tip and a lease when replacing a snapshot.
        expected = git('rev-parse', 'FETCH_HEAD')
    if mode == 'history' and branch == default and expected and expected != git('rev-parse', 'HEAD'):
        raise RuntimeError('Default branch changed during validation; rerun with current config')
    with tempfile.TemporaryDirectory(prefix='proxy-git-') as temporary:
        env = os.environ.copy()
        env.update(GIT_INDEX_FILE=str(Path(temporary) / 'index'),
                   GIT_AUTHOR_NAME='github-actions[bot]', GIT_COMMITTER_NAME='github-actions[bot]',
                   GIT_AUTHOR_EMAIL='41898282+github-actions[bot]@users.noreply.github.com',
                   GIT_COMMITTER_EMAIL='41898282+github-actions[bot]@users.noreply.github.com')
        if mode == 'history':
            git('read-tree', expected or 'HEAD', env=env)
        else:
            git('read-tree', '--empty', env=env)
        git('add', '-A', '--', 'proxies', env=env)
        tree = git('write-tree', env=env)
        if expected and tree == git('rev-parse', f'{expected}^{{tree}}'):
            print('No files changed; nothing to commit.')
            return
        parents = ['-p', expected or git('rev-parse', 'HEAD')] if mode == 'history' else []
        commit = git('commit-tree', tree, *parents, env=env,
                     input=f"Refresh verified proxies ({meta['timestamp']})\n")
        flags = [f'--force-with-lease={ref}:{expected}'] if mode == 'snapshot' else []
        git('push', *flags, 'origin', f'{commit}:{ref}')
        print(f'Published verified results to {branch} ({commit[:12]}).')


if __name__ == '__main__':
    publish()
