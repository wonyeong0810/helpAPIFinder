from contextlib import closing
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from help_api_finder.db import Database, FindingInput


def sample_finding() -> FindingInput:
    return FindingInput(
        provider="OpenAI",
        label="OpenAI API key",
        fingerprint="a" * 64,
        masked_secret="••••••••9zC0",
        repository="new-user/hello-ai",
        owner="new-user",
        repo_url="https://github.com/new-user/hello-ai",
        owner_url="https://github.com/new-user",
        beginner_score=8,
        beginner_signals=json.dumps(["공개 저장소 10개 이하", "팔로워 없음"], ensure_ascii=False),
        file_path="app.py",
        file_url="https://github.com/new-user/hello-ai/blob/a/app.py#L2",
        line_number=2,
        commit_sha="a" * 40,
        evidence="OPENAI_API_KEY=[REDACTED]",
        confidence="high",
    )


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.temp.name) / "findings.db")

    def tearDown(self):
        self.temp.cleanup()

    def test_upsert_deduplicates_and_counts_rescans(self):
        self.assertTrue(self.db.upsert_finding(sample_finding()))
        self.assertFalse(self.db.upsert_finding(sample_finding()))
        result = self.db.list_findings()
        self.assertEqual(result["total"], 1)
        self.assertEqual(result["items"][0]["scan_count"], 2)
        self.assertEqual(result["items"][0]["beginner_score"], 8)
        self.assertEqual(result["items"][0]["beginner_signals"][0], "공개 저장소 10개 이하")
        self.assertNotIn("fingerprint", result["items"][0]["evidence"])

    def test_status_and_summary(self):
        self.db.upsert_finding(sample_finding())
        finding_id = self.db.list_findings()["items"][0]["id"]
        self.assertTrue(self.db.update_finding_status(finding_id, "notified"))
        summary = self.db.summary()
        self.assertEqual(summary["notified"], 1)
        self.assertEqual(summary["new"], 0)

    def test_rejects_unknown_status(self):
        with self.assertRaises(ValueError):
            self.db.update_finding_status(1, "deleted")

    def test_migrates_existing_database_with_beginner_fields(self):
        legacy_path = Path(self.temp.name) / "legacy.db"
        with closing(sqlite3.connect(legacy_path)) as connection:
            connection.execute(
                "CREATE TABLE findings (id INTEGER PRIMARY KEY, status TEXT, provider TEXT, last_seen_at TEXT)"
            )
            connection.commit()
        migrated = Database(legacy_path)
        with migrated.connect() as connection:
            columns = {
                row["name"] for row in connection.execute("PRAGMA table_info(findings)").fetchall()
            }
        self.assertIn("beginner_score", columns)
        self.assertIn("beginner_signals", columns)

    def test_marks_interrupted_scan_after_restart(self):
        scan_id = self.db.create_scan("is:public")
        self.assertEqual(self.db.mark_interrupted_scans(), 1)
        scan = self.db.latest_scan()
        self.assertEqual(scan["id"], scan_id)
        self.assertEqual(scan["status"], "failed")
        self.assertIn("재시작", scan["error_message"])

    def test_processed_owners_are_persistent_and_case_insensitive(self):
        self.db.mark_owner_processed("New-User", finding_detected=False)
        self.db.mark_owner_processed("new-user", finding_detected=True)

        self.assertEqual(self.db.processed_owners(), {"new-user"})
        with self.db.connect() as connection:
            row = connection.execute(
                "SELECT COUNT(*) AS count, finding_detected FROM processed_owners"
            ).fetchone()
        self.assertEqual(row["count"], 1)
        self.assertEqual(row["finding_detected"], 1)

    def test_existing_finding_owner_is_treated_as_processed(self):
        self.db.upsert_finding(sample_finding())
        self.assertIn("new-user", self.db.processed_owners())


if __name__ == "__main__":
    unittest.main()
