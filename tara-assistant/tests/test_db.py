import sqlite3

from app import config, db


def test_init_db_migrates_existing_review_history(env):
    with sqlite3.connect(config.DB_PATH) as connection:
        connection.execute(
            "CREATE TABLE reviews(id INTEGER PRIMARY KEY, item_id INTEGER, reviewer TEXT, "
            "decision TEXT, rationale TEXT, ts TEXT)"
        )
    db.init_db()
    with db.conn() as connection:
        columns = {row["name"] for row in connection.execute("PRAGMA table_info(reviews)")}
    assert {"previous_status", "new_status"} <= columns
