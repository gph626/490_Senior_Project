import os
import sys

# Ensure repo root is on sys.path when running the script directly
repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if repo_root not in sys.path:
	sys.path.insert(0, repo_root)

from backend import database  # noqa: E402


def test_db_init_and_insert():
	database.init_db()
	nid = database.insert_leak(source='test', url='http://example.local', data='sample data', severity='low')
	assert nid is not None
	latest = database.get_latest_leaks(1)
	assert len(latest) == 1
	print('Latest leak id:', latest[0].id)


if __name__ == '__main__':
	test_db_init_and_insert()
