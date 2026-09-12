from datetime import UTC, datetime
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from help_api_finder.db import Database
from help_api_finder.github import GitHubError
from help_api_finder.service import ScanConfig, ScanManager


class ScanManagerTests(unittest.TestCase):
    def test_skips_processed_repository_and_marks_new_repository(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Database(Path(directory) / "findings.db")
            database.mark_repository_processed(
                "seen-owner/old-project",
                "seen-owner",
                finding_detected=False,
            )
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
            self.assertEqual(
                database.processed_repositories(),
                {"seen-owner/old-project", "fresh-owner/first-project"},
            )

    def test_scans_new_repository_for_owner_without_findings(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Database(Path(directory) / "findings.db")
            database.mark_repository_processed(
                "returning-owner/old-project",
                "returning-owner",
                finding_detected=False,
            )
            calls: list[str] = []

            class FakeGitHubClient:
                rate_remaining = 4999
                rate_reset = 0

                def __init__(self, token: str):
                    self.token = token

                def search_repositories(self, query: str, limit: int):
                    return [{
                        "private": False,
                        "visibility": "public",
                        "owner": {
                            "type": "User",
                            "login": "returning-owner",
                            "html_url": "https://github.com/returning-owner",
                        },
                        "name": "new-project",
                        "full_name": "returning-owner/new-project",
                        "html_url": "https://github.com/returning-owner/new-project",
                        "default_branch": "main",
                        "description": "my first project",
                        "topics": [],
                        "stargazers_count": 0,
                        "forks_count": 0,
                        "size": 100,
                        "license": None,
                    }]

                def get_user(self, login: str):
                    calls.append(login)
                    return {
                        "public_repos": 2,
                        "followers": 0,
                        "created_at": datetime.now(UTC).isoformat(),
                    }

                def get_commit_sha(self, full_name: str, ref: str):
                    return "b" * 40

                def iter_archive_files(self, full_name: str, commit_sha: str, *, max_files: int):
                    yield "README.md", "hello"

            manager = ScanManager(database, b"f" * 32)
            scan_id = database.create_scan(ScanConfig().query())
            with patch("help_api_finder.service.GitHubClient", FakeGitHubClient):
                manager._run(scan_id, ScanConfig(), "test-token")

            self.assertEqual(calls, ["returning-owner"])
            self.assertIn(
                "returning-owner/new-project",
                database.processed_repositories(),
            )

    def test_skips_new_repository_after_owner_has_finding(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Database(Path(directory) / "findings.db")
            database.mark_owner_processed("found-owner", finding_detected=True)

            class FakeGitHubClient:
                rate_remaining = 4999
                rate_reset = 0

                def __init__(self, token: str):
                    self.token = token

                def search_repositories(self, query: str, limit: int):
                    return [{
                        "private": False,
                        "visibility": "public",
                        "owner": {"type": "User", "login": "found-owner"},
                        "full_name": "found-owner/new-project",
                    }]

                def get_user(self, login: str):
                    raise AssertionError("owner with a finding must be skipped")

            manager = ScanManager(database, b"f" * 32)
            scan_id = database.create_scan(ScanConfig().query())
            with patch("help_api_finder.service.GitHubClient", FakeGitHubClient):
                manager._run(scan_id, ScanConfig(), "test-token")

            self.assertEqual(database.latest_scan()["repositories_scanned"], 0)

    def test_http_409_repository_is_skipped_without_failing_scan(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Database(Path(directory) / "findings.db")

            class FakeGitHubClient:
                rate_remaining = 4990
                rate_reset = 0

                def __init__(self, token: str):
                    self.token = token

                def search_repositories(self, query: str, limit: int):
                    return [
                        self._repository("empty-owner", "empty-repo"),
                        self._repository("ready-owner", "ready-repo"),
                    ]

                def get_user(self, login: str):
                    return {
                        "public_repos": 1,
                        "followers": 0,
                        "created_at": datetime.now(UTC).isoformat(),
                    }

                def get_commit_sha(self, full_name: str, ref: str):
                    if full_name == "empty-owner/empty-repo":
                        raise GitHubError(
                            "GitHub API request failed (HTTP 409).",
                            status_code=409,
                        )
                    return "c" * 40

                def iter_archive_files(self, full_name: str, commit_sha: str, *, max_files: int):
                    yield "README.md", "hello"

                @staticmethod
                def _repository(owner: str, name: str):
                    return {
                        "private": False,
                        "visibility": "public",
                        "owner": {"type": "User", "login": owner},
                        "name": name,
                        "full_name": f"{owner}/{name}",
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
            self.assertNotIn(
                "empty-owner/empty-repo",
                database.processed_repositories(),
            )
            self.assertIn(
                "ready-owner/ready-repo",
                database.processed_repositories(),
            )


if __name__ == "__main__":
    unittest.main()
