import base64
from io import BytesIO
import json
import tempfile
import unittest
from pathlib import Path
from wsgiref.util import setup_testing_defaults

from help_api_finder.db import Database
from help_api_finder.service import ScanManager
from help_api_finder.wsgi import KeylightApplication


class WSGITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        database = Database(Path(self.temp.name) / "findings.db")
        manager = ScanManager(database, b"test-fingerprint-key")
        self.app = KeylightApplication(
            database,
            manager,
            username="admin",
            password="long-test-password",
            require_auth=True,
            allowed_hosts={"keys.example.test"},
            public_origin="https://keys.example.test",
        )

    def tearDown(self):
        self.temp.cleanup()

    def request(self, path="/", *, method="GET", auth=True, body=None, headers=None, host="keys.example.test"):
        environ = {}
        setup_testing_defaults(environ)
        environ["REQUEST_METHOD"] = method
        parsed_path, _, query = path.partition("?")
        environ["PATH_INFO"] = parsed_path
        environ["QUERY_STRING"] = query
        environ["HTTP_HOST"] = host
        if auth:
            credentials = base64.b64encode(b"admin:long-test-password").decode("ascii")
            environ["HTTP_AUTHORIZATION"] = f"Basic {credentials}"
        if headers:
            environ.update(headers)
        data = json.dumps(body).encode("utf-8") if body is not None else b""
        environ["wsgi.input"] = BytesIO(data)
        environ["CONTENT_LENGTH"] = str(len(data))
        if body is not None:
            environ["CONTENT_TYPE"] = "application/json"
        captured = {}

        def start_response(status, response_headers):
            captured["status"] = status
            captured["headers"] = dict(response_headers)

        response = b"".join(self.app(environ, start_response))
        return captured["status"], captured["headers"], response

    def test_healthz_is_available_without_authentication(self):
        status, _, body = self.request("/healthz", auth=False, host="container-internal")
        self.assertEqual(status, "200 OK")
        self.assertTrue(json.loads(body)["ok"])

    def test_dashboard_requires_authentication(self):
        status, headers, _ = self.request(auth=False)
        self.assertEqual(status, "401 Unauthorized")
        self.assertIn("Basic", headers["WWW-Authenticate"])

    def test_dashboard_rejects_wrong_host(self):
        status, _, _ = self.request(host="attacker.example")
        self.assertEqual(status, "403 Forbidden")

    def test_malformed_authorization_is_rejected(self):
        status, _, _ = self.request(auth=False, headers={"HTTP_AUTHORIZATION": "Basic !!!"})
        self.assertEqual(status, "401 Unauthorized")

    def test_mutation_requires_dashboard_header(self):
        status, _, _ = self.request(
            "/api/scans",
            method="POST",
            body={"recent_days": 7, "max_repositories": 1},
        )
        self.assertEqual(status, "403 Forbidden")

    def test_mutation_rejects_wrong_origin(self):
        status, _, _ = self.request(
            "/api/scans",
            method="POST",
            body={"recent_days": 7, "max_repositories": 1},
            headers={
                "HTTP_X_KEYLIGHT_REQUEST": "dashboard",
                "HTTP_ORIGIN": "https://attacker.example",
            },
        )
        self.assertEqual(status, "403 Forbidden")

    def test_repeated_auth_failures_are_rate_limited(self):
        for _ in range(10):
            status, _, _ = self.request(auth=False)
            self.assertEqual(status, "401 Unauthorized")
        status, headers, _ = self.request(auth=False)
        self.assertEqual(status, "429 Too Many Requests")
        self.assertEqual(headers["Retry-After"], "300")

    def test_authenticated_summary_has_security_headers(self):
        status, headers, body = self.request("/api/summary")
        self.assertEqual(status, "200 OK")
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertEqual(json.loads(body)["total"], 0)


if __name__ == "__main__":
    unittest.main()
