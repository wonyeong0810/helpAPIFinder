from datetime import UTC, datetime
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from help_api_finder.db import Database
from help_api_finder.service import ScanConfig, ScanManager


class ScanManagerTests(unittest.TestCase):
    def test_skips_processed_owner_and_marks_new_owner(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Database(Path(directory) / "findings.db")
            database.mark_owner_processed("seen-owner", finding_detected=False)
            calls: list[str] = []

            class FakeGitHubClient:
                rate_remaining = 4999
                rate_reset = 0

                def __init__(self, token: str):
                    self.token = token

                def search_repositories(self, query: str, limit: int):
                    return [
                        self._repository("seen-owner", "old-project"),
                        self._repository("fresh-owner", "first-project"),
                    ]

                def get_user(self, login: str):
                    calls.append(login)
                    return {
                        "public_repos": 1,
                        "followers": 0,
                        "created_at": datetime.now(UTC).isoformat(),
                    }

                def get_commit_sha(self, full_name: str, ref: str):
                    return "a" * 40

                def iter_archive_files(self, full_name: str, commit_sha: str, *, max_files: int):
                    yield "README.md", "hello"

                @staticmethod
                def _repository(owner: str, name: str):
                    return {
                        "private": False,
                        "visibility": "public",
                        "owner": {
                            "type": "User",
                            "login": owner,
                            "html_url": f"https://github.com/{owner}",
                        },
                        "name": name,
                        "full_name": f"{owner}/{name}",
                        "html_url": f"https://github.com/{owner}/{name}",
                        "default_branch": "main",
                        "description": "my first project",
                        "topics": [],
                        "stargazers_count": 0,
                        "forks_count": 0,
                        "size": 100,
                        "license": None,
                    }

            manager = ScanManager(database, b"f" * 32)
            scan_id = database.create_scan(ScanConfig().query())
            with patch("help_api_finder.service.GitHubClient", FakeGitHubClient):
                manager._run(scan_id, ScanConfig(), "test-token")

            scan = database.latest_scan()
            self.assertEqual(scan["status"], "completed")
            self.assertEqual(scan["repositories_scanned"], 1)
            self.assertEqual(calls, ["fresh-owner"])
            self.assertEqual(database.processed_owners(), {"seen-owner", "fresh-owner"})


if __name__ == "__main__":
    unittest.main()
