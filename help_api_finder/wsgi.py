from __future__ import annotations

import base64
from collections import defaultdict, deque
import hmac
import json
import mimetypes
import os
from pathlib import Path
import re
import threading
import time
import urllib.parse
from typing import Any, Callable, Iterable

from .db import Database
from .patterns import supported_providers
from .service import ScanConfig, ScanManager, _read_secret


STATIC_ROOT = Path(__file__).resolve().parent.parent / "static"
MAX_BODY_BYTES = 64 * 1024
StartResponse = Callable[[str, list[tuple[str, str]]], Any]


class KeylightApplication:
    def __init__(
        self,
        database: Database,
        manager: ScanManager,
        *,
        username: str = "",
        password: str = "",
        require_auth: bool = False,
        allowed_hosts: set[str] | None = None,
        public_origin: str = "",
        trust_proxy: bool = False,
    ):
        if require_auth and (not username or not password):
            raise RuntimeError(
                "KEYLIGHT_REQUIRE_AUTH=1이면 관리자 사용자명과 비밀번호가 필요합니다."
            )
        self.database = database
        self.manager = manager
        self.auth_enabled = require_auth or bool(username and password)
        self.username = username
        self.password = password
        self.allowed_hosts = {host.lower().rstrip(".") for host in (allowed_hosts or set())}
        self.public_origin = public_origin.rstrip("/")
        self.trust_proxy = trust_proxy
        self._auth_failures: dict[str, deque[float]] = defaultdict(deque)
        self._auth_lock = threading.Lock()

    def __call__(self, environ: dict[str, Any], start_response: StartResponse) -> Iterable[bytes]:
        method = str(environ.get("REQUEST_METHOD", "GET")).upper()
        path = str(environ.get("PATH_INFO", "/"))

        if method == "GET" and path == "/healthz":
            return self._json(start_response, {"ok": True})
        if not self._valid_host(environ):
            return self._json(start_response, {"error": "허용되지 않은 호스트입니다."}, "403 Forbidden")
        if self.auth_enabled:
            client = self._client_address(environ)
            if self._auth_limited(client):
                return self._json(
                    start_response,
                    {"error": "인증 시도가 너무 많습니다. 잠시 후 다시 시도하세요."},
                    "429 Too Many Requests",
                    [("Retry-After", "300")],
                )
            if not self._authenticated(environ):
                self._record_auth_failure(client)
                return self._json(
                    start_response,
                    {"error": "관리자 인증이 필요합니다."},
                    "401 Unauthorized",
                    [("WWW-Authenticate", 'Basic realm="Keylight", charset="UTF-8"')],
                )
            self._clear_auth_failures(client)
        if method in {"POST", "PATCH"} and not self._valid_mutation_request(environ):
            return self._json(start_response, {"error": "요청 출처를 확인할 수 없습니다."}, "403 Forbidden")

        try:
            if method == "GET" and path == "/api/health":
                return self._json(
                    start_response,
                    {"ok": True, "authenticated": self.auth_enabled},
                )
            if method == "GET" and path == "/api/summary":
                summary = self.database.summary()
                summary["providers_supported"] = list(supported_providers())
                return self._json(start_response, summary)
            if method == "GET" and path == "/api/scans/latest":
                return self._json(
                    start_response,
                    {
                        "scan": self.database.latest_scan(),
                        "running": self.manager.running,
                        "schedule": self.manager.schedule_status(),
                    },
                )
            if method == "GET" and path == "/api/findings":
                params = urllib.parse.parse_qs(str(environ.get("QUERY_STRING", "")))
                result = self.database.list_findings(
                    status=_first(params, "status"),
                    provider=_first(params, "provider"),
                    search=_first(params, "q"),
                    limit=int(_first(params, "limit") or 100),
                    offset=int(_first(params, "offset") or 0),
                )
                return self._json(start_response, result)
            if method == "POST" and path == "/api/scans":
                config = ScanConfig.from_payload(self._body_json(environ))
                scan_id = self.manager.start(config)
                return self._json(
                    start_response,
                    {"scan_id": scan_id, "status": "running"},
                    "202 Accepted",
                )
            finding_match = re.fullmatch(r"/api/findings/(\d+)", path)
            if method == "PATCH" and finding_match:
                status = str(self._body_json(environ).get("status", ""))
                updated = self.database.update_finding_status(int(finding_match.group(1)), status)
                if not updated:
                    return self._json(
                        start_response,
                        {"error": "탐지 결과를 찾을 수 없습니다."},
                        "404 Not Found",
                    )
                return self._json(start_response, {"ok": True})
            if method == "GET" and path in {"/", "/index.html"}:
                return self._static(start_response, "index.html")
            if method == "GET" and path in {"/static/app.js", "/static/styles.css"}:
                return self._static(start_response, path.rsplit("/", 1)[-1])
            return self._json(start_response, {"error": "찾을 수 없습니다."}, "404 Not Found")
        except ValueError as error:
            return self._json(start_response, {"error": str(error)}, "400 Bad Request")
        except RuntimeError as error:
            return self._json(start_response, {"error": str(error)}, "409 Conflict")

    def _authenticated(self, environ: dict[str, Any]) -> bool:
        authorization = str(environ.get("HTTP_AUTHORIZATION", ""))
        if len(authorization) > 4096 or not authorization.startswith("Basic "):
            return False
        try:
            decoded = base64.b64decode(authorization[6:], validate=True).decode("utf-8")
            username, password = decoded.split(":", 1)
        except (ValueError, UnicodeDecodeError):
            return False
        return hmac.compare_digest(username, self.username) and hmac.compare_digest(
            password, self.password
        )

    def _client_address(self, environ: dict[str, Any]) -> str:
        if self.trust_proxy:
            forwarded = str(environ.get("HTTP_X_FORWARDED_FOR", "")).split(",", 1)[0].strip()
            if forwarded:
                return forwarded[:128]
        return str(environ.get("REMOTE_ADDR", "unknown"))[:128]

    def _auth_limited(self, client: str) -> bool:
        cutoff = time.monotonic() - 300
        with self._auth_lock:
            failures = self._auth_failures[client]
            while failures and failures[0] < cutoff:
                failures.popleft()
            return len(failures) >= 10

    def _record_auth_failure(self, client: str) -> None:
        with self._auth_lock:
            self._auth_failures[client].append(time.monotonic())

    def _clear_auth_failures(self, client: str) -> None:
        with self._auth_lock:
            self._auth_failures.pop(client, None)

    def _valid_host(self, environ: dict[str, Any]) -> bool:
        if not self.allowed_hosts:
            return True
        host = str(environ.get("HTTP_HOST", "")).split(":", 1)[0].lower().rstrip(".")
        return host in self.allowed_hosts

    def _valid_mutation_request(self, environ: dict[str, Any]) -> bool:
        if environ.get("HTTP_X_KEYLIGHT_REQUEST") != "dashboard":
            return False
        origin = str(environ.get("HTTP_ORIGIN", "")).rstrip("/")
        return not self.public_origin or not origin or hmac.compare_digest(origin, self.public_origin)

    @staticmethod
    def _body_json(environ: dict[str, Any]) -> dict[str, Any]:
        content_type = str(environ.get("CONTENT_TYPE", "")).split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            raise ValueError("application/json 요청만 허용됩니다.")
        try:
            length = int(environ.get("CONTENT_LENGTH") or "0")
        except ValueError:
            raise ValueError("요청 크기가 올바르지 않습니다.") from None
        if length < 0 or length > MAX_BODY_BYTES:
            raise ValueError("요청이 너무 큽니다.")
        try:
            payload = json.loads(environ["wsgi.input"].read(length) or b"{}")
        except (KeyError, json.JSONDecodeError):
            raise ValueError("JSON 형식이 올바르지 않습니다.") from None
        if not isinstance(payload, dict):
            raise ValueError("JSON 객체가 필요합니다.")
        return payload

    def _static(self, start_response: StartResponse, name: str) -> Iterable[bytes]:
        try:
            data = (STATIC_ROOT / name).read_bytes()
        except FileNotFoundError:
            return self._json(start_response, {"error": "정적 파일을 찾을 수 없습니다."}, "404 Not Found")
        mime = mimetypes.guess_type(name)[0] or "application/octet-stream"
        return self._response(start_response, data, "200 OK", f"{mime}; charset=utf-8")

    def _json(
        self,
        start_response: StartResponse,
        payload: Any,
        status: str = "200 OK",
        extra_headers: list[tuple[str, str]] | None = None,
    ) -> Iterable[bytes]:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        return self._response(
            start_response,
            data,
            status,
            "application/json; charset=utf-8",
            extra_headers,
        )

    @staticmethod
    def _response(
        start_response: StartResponse,
        data: bytes,
        status: str,
        content_type: str,
        extra_headers: list[tuple[str, str]] | None = None,
    ) -> Iterable[bytes]:
        headers = [
            ("Content-Type", content_type),
            ("Content-Length", str(len(data))),
            ("Cache-Control", "no-store"),
            ("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"),
            ("Referrer-Policy", "no-referrer"),
            ("X-Content-Type-Options", "nosniff"),
            ("X-Frame-Options", "DENY"),
            ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
            ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
        ]
        headers.extend(extra_headers or [])
        start_response(status, headers)
        return [data]


def create_application() -> KeylightApplication:
    db_path = Path(os.environ.get("FINDER_DB_PATH", ".data/findings.db"))
    from .db import load_fingerprint_key

    database = Database(db_path)
    database.mark_interrupted_scans()
    manager = ScanManager(database, load_fingerprint_key(db_path))

    interval_minutes = _env_int("FINDER_SCAN_INTERVAL_MINUTES", 0, 0, 43_200)
    if interval_minutes:
        if not _read_secret("GITHUB_TOKEN", "GITHUB_TOKEN_FILE"):
            raise RuntimeError("자동 검사를 사용하려면 GitHub token secret이 필요합니다.")
        manager.enable_schedule(
            ScanConfig.from_payload(
                {
                    "recent_days": _env_int("FINDER_RECENT_DAYS", 7, 1, 30),
                    "max_repositories": _env_int("FINDER_MAX_REPOSITORIES", 10, 1, 25),
                }
            ),
            interval_minutes,
        )

    require_auth = _env_bool("KEYLIGHT_REQUIRE_AUTH", False)
    username = os.environ.get("KEYLIGHT_ADMIN_USERNAME", "")
    password = _read_secret("KEYLIGHT_ADMIN_PASSWORD", "KEYLIGHT_ADMIN_PASSWORD_FILE")
    allowed_hosts = {
        item.strip() for item in os.environ.get("KEYLIGHT_ALLOWED_HOSTS", "").split(",") if item.strip()
    }
    return KeylightApplication(
        database,
        manager,
        username=username,
        password=password,
        require_auth=require_auth,
        allowed_hosts=allowed_hosts,
        public_origin=os.environ.get("KEYLIGHT_PUBLIC_ORIGIN", ""),
        trust_proxy=_env_bool("KEYLIGHT_TRUST_PROXY", False),
    )


def _env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except ValueError:
        raise RuntimeError(f"{name} 값은 숫자여야 합니다.") from None
    if not minimum <= value <= maximum:
        raise RuntimeError(f"{name} 값은 {minimum}~{maximum} 범위여야 합니다.")
    return value


def _first(params: dict[str, list[str]], key: str) -> str:
    values = params.get(key)
    return values[0] if values else ""
