import unittest

from help_api_finder.github import _file_priority, _is_candidate_file
from help_api_finder.service import ScanConfig, _assess_beginner


class GitHubSelectionTests(unittest.TestCase):
    def test_selects_source_and_env_files(self):
        self.assertTrue(_is_candidate_file("src/app.py", 1200))
        self.assertTrue(_is_candidate_file(".env.local", 200))
        self.assertFalse(_is_candidate_file("node_modules/pkg/index.js", 200))
        self.assertFalse(_is_candidate_file("package-lock.json", 200))
        self.assertFalse(_is_candidate_file("image.png", 200))

    def test_prioritizes_secret_configuration(self):
        self.assertLess(_file_priority(".env"), _file_priority("src/app.py"))

    def test_scan_bounds(self):
        with self.assertRaises(ValueError):
            ScanConfig.from_payload({"recent_days": 31, "max_repositories": 10})
        with self.assertRaises(ValueError):
            ScanConfig.from_payload({"recent_days": 7, "max_repositories": 26})

    def test_query_is_explicitly_public(self):
        query = ScanConfig().query()
        self.assertIn("is:public", query)
        self.assertIn("fork:false", query)
        self.assertIn("pushed:", query)
        self.assertNotIn("created:", query)

    def test_old_low_activity_account_can_be_beginner_candidate(self):
        user = {"public_repos": 5, "followers": 0, "created_at": "2012-01-01T00:00:00Z"}
        repository = {
            "name": "tiny-api",
            "description": "",
            "topics": [],
            "stargazers_count": 0,
            "forks_count": 0,
            "size": 400,
            "license": None,
        }
        score, signals = _assess_beginner(user, repository)
        self.assertGreaterEqual(score, ScanConfig().minimum_beginner_score)
        self.assertNotIn("계정 활동 6개월 이내", signals)
        self.assertIn("팔로워 없음", signals)

    def test_established_account_is_not_prioritized_by_small_repo_alone(self):
        user = {"public_repos": 120, "followers": 800, "created_at": "2010-01-01T00:00:00Z"}
        repository = {
            "name": "production-api",
            "description": "",
            "topics": [],
            "stargazers_count": 0,
            "forks_count": 0,
            "size": 400,
            "license": None,
        }
        score, _ = _assess_beginner(user, repository)
        self.assertLess(score, ScanConfig().minimum_beginner_score)

    def test_learning_project_adds_explainable_signal(self):
        score, signals = _assess_beginner(
            {"public_repos": 30, "followers": 10, "created_at": "2012-01-01T00:00:00Z"},
            {
                "name": "python-practice",
                "description": "my first project",
                "topics": [],
                "stargazers_count": 1,
                "forks_count": 2,
                "size": 9000,
                "license": {"key": "mit"},
            },
        )
        self.assertEqual(score, 2)
        self.assertIn("학습·연습형 프로젝트", signals)


if __name__ == "__main__":
    unittest.main()
