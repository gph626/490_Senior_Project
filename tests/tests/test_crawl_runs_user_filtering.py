from backend.database import insert_crawl_run, get_crawl_runs_for_user

def test_crawl_runs_are_filtered_by_user():
    # Insert runs for two different users
    run1_id = insert_crawl_run(source="pastebin", user_id=1, status="completed")
    run2_id = insert_crawl_run(source="tor", user_id=2, status="running")
    run3_id = insert_crawl_run(source="i2p", user_id=1, status="completed")

    # Fetch runs for user_id=1
    runs_user1 = get_crawl_runs_for_user(1)
    sources_user1 = {r.source for r in runs_user1}
    assert "pastebin" in sources_user1
    assert "i2p" in sources_user1
    assert "tor" not in sources_user1  # should NOT see user 2's run

    # Fetch runs for user_id=2
    runs_user2 = get_crawl_runs_for_user(2)
    sources_user2 = {r.source for r in runs_user2}
    assert "tor" in sources_user2
    assert "pastebin" not in sources_user2
    assert "i2p" not in sources_user2
