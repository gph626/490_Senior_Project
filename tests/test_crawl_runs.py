# tests/test_crawl_runs.py
import pytest
from backend.database import insert_crawl_run, get_crawl_runs_for_user

def test_get_crawl_runs_for_user(tmp_path):
    """
    Ensure get_crawl_runs_for_user() only returns crawl runs that belong
    to the specified user_id.
    """
    # Insert crawl runs for two different users
    run_id_user1_a = insert_crawl_run(source="pastebin", user_id=1, status="completed")
    run_id_user1_b = insert_crawl_run(source="tor", user_id=1, status="running")
    run_id_user2_a = insert_crawl_run(source="i2p", user_id=2, status="completed")

    # Fetch crawl runs for user_id = 1
    user1_runs = get_crawl_runs_for_user(1)
    user1_run_ids = {r.id for r in user1_runs}

    # Fetch crawl runs for user_id = 2
    user2_runs = get_crawl_runs_for_user(2)
    user2_run_ids = {r.id for r in user2_runs}

    # ✅ Assertions
    assert run_id_user1_a in user1_run_ids
    assert run_id_user1_b in user1_run_ids
    assert run_id_user2_a not in user1_run_ids

    assert run_id_user2_a in user2_run_ids
    assert run_id_user1_a not in user2_run_ids
    assert run_id_user1_b not in user2_run_ids

    # Sanity check: no overlap between the two sets
    assert user1_run_ids.isdisjoint(user2_run_ids)
