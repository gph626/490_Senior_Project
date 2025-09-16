import os
import sys

repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from backend import database


def run_test():
    database.init_db()
    normalized = {'title': 'Sample Paste', 'entities': [], 'source_type': 'paste'}
    nid = database.insert_leak(source='paste_test', url='http://paste.local/1', data='raw content', severity='medium', normalized=normalized)
    print('Inserted id:', nid)
    latest = database.get_latest_leaks(1)
    assert len(latest) == 1
    row = latest[0]
    assert row.source == 'paste_test'
    assert row.normalized is not None
    print('Normalized stored:', row.normalized)


if __name__ == '__main__':
    run_test()
