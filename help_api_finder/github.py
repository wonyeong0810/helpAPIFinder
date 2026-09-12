from __future__ import annotations

import io
import json
import re
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from typing import Any, Iterator


API_ROOT = "https://api.github.com"
CODELOAD_ROOT = "https://codeload.github.com"
USER_AGENT = "Keylight-Defensive-Secret-Notifier/0.1"
MAX_JSON_BYTES = 12 * 1024 * 1024
MAX_ARCHIVE_BYTES = 24 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 64 * 1024 * 1024
MAX_FILE_BYTES = 512 * 1024


class GitHubError(RuntimeError):
    def __init__(self, message: str, *, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


class GitHubClient:
    def __init__(self, token: str, *, api_root: str = API_ROOT):
        if not token.strip():
            raise ValueError("GITHUB_TOKEN 환경변수가 필요합니다.")
        self._token = token.strip()
        self.api_root = api_root.rstrip("/")
        self.rate_remaining: int | None = None
        self.rate_reset: int | None = None

    def _api_json(self, path: str, query: dict[str, Any] | None = None) -> Any:
        url = f"{self.api_root}{path}"
        if query:
            url = f"{url}?{urllib.parse.urlencode(query)}"
        request = urllib.request.Request(
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self._token}",
                "User-Agent": USER_AGENT,
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=25) as response:
                self._capture_rate(response.headers)
                payload = _bounded_read(response, MAX_JSON_BYTES)
                return json.loads(payload.decode("utf-8"))
        except urllib.error.HTTPError as error:
            self._capture_rate(error.headers)
            message = _safe_api_error(error)
            raise GitHubError(message, status_code=error.code) from None
        except urllib.error.URLError as error:
            raise GitHubError(f"GitHub 연결 실패: {error.reason}") from None
        except (TimeoutError, json.JSONDecodeError):
            raise GitHubError("GitHub 응답을 처리하지 못했습니다.") from None

    def _capture_rate(self, headers: Any) -> None:
        remaining = headers.get("X-RateLimit-Remaining") if headers else None
        reset = headers.get("X-RateLimit-Reset") if headers else None
        self.rate_remaining = int(remaining) if remaining and remaining.isdigit() else self.rate_remaining
        self.rate_reset = int(reset) if reset and reset.isdigit() else self.rate_reset

    def search_repositories(self, query: str, limit: int) -> list[dict[str, Any]]:
        result = self._api_json(
            "/search/repositories",
            {"q": query, "sort": "updated", "order": "desc", "per_page": min(limit, 100)},
        )
        return list(result.get("items", []))[:limit]

    def get_user(self, login: str) -> dict[str, Any]:
        return self._api_json(f"/users/{urllib.parse.quote(login, safe='')}")

    def get_commit_sha(self, full_name: str, ref: str) -> str:
        owner, repo = _split_full_name(full_name)
        payload = self._api_json(
            f"/repos/{urllib.parse.quote(owner, safe='')}/{urllib.parse.quote(repo, safe='')}/commits/"
            f"{urllib.parse.quote(ref, safe='')}"
        )
        sha = str(payload.get("sha", ""))
        if not re.fullmatch(r"[0-9a-f]{40}", sha):
            raise GitHubError("저장소 커밋 식별자가 올바르지 않습니다.")
        return sha

    def iter_archive_files(
        self, full_name: str, commit_sha: str, *, max_files: int
    ) -> Iterator[tuple[str, str]]:
        """Yield bounded text files from a public repository archive.

        This codeload request deliberately carries no GitHub token.
        """
        owner, repo = _split_full_name(full_name)
        if not re.fullmatch(r"[0-9a-f]{40}", commit_sha):
            raise GitHubError("저장소 커밋 식별자가 올바르지 않습니다.")
        url = (
            f"{CODELOAD_ROOT}/{urllib.parse.quote(owner, safe='')}/"
            f"{urllib.parse.quote(repo, safe='')}/zip/{commit_sha}"
        )
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(request, timeout=45) as response:
                archive = _bounded_read(response, MAX_ARCHIVE_BYTES)
        except urllib.error.HTTPError as error:
            raise GitHubError(
                f"공개 저장소 아카이브를 읽지 못했습니다 (HTTP {error.code}).",
                status_code=error.code,
            ) from None
        except urllib.error.URLError as error:
            raise GitHubError(f"저장소 다운로드 실패: {error.reason}") from None

        try:
            with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
                infos = [item for item in bundle.infolist() if not item.is_dir()]
                if sum(item.file_size for item in infos) > MAX_UNCOMPRESSED_BYTES:
                    raise GitHubError("압축 해제 크기 제한을 넘은 저장소라 건너뜁니다.")
                candidates = sorted(
                    (item for item in infos if _is_candidate_file(_strip_archive_root(item.filename), item.file_size)),
                    key=lambda item: _file_priority(_strip_archive_root(item.filename)),
                )[:max_files]
                for item in candidates:
                    path = _strip_archive_root(item.filename)
                    raw = bundle.read(item)
                    if b"\x00" in raw[:4096]:
                        continue
                    yield path, raw.decode("utf-8", errors="replace")
        except zipfile.BadZipFile:
            raise GitHubError("저장소 아카이브 형식이 올바르지 않습니다.") from None


def _bounded_read(response: Any, limit: int) -> bytes:
    payload = response.read(limit + 1)
    if len(payload) > limit:
        raise GitHubError("원격 응답이 안전 크기 제한을 넘었습니다.")
    return payload


def _safe_api_error(error: urllib.error.HTTPError) -> str:
    if error.code == 429 or (error.headers and error.headers.get("Retry-After")):
        return "GitHub API가 요청 속도를 제한했습니다. 다음 예약 검사에서 다시 시도합니다."
    if error.code in (401, 403):
        if error.headers and error.headers.get("X-RateLimit-Remaining") == "0":
            return "GitHub API 요청 한도에 도달했습니다. 재설정 후 다시 시도하세요."
        return "GitHub 토큰 권한 또는 접근 설정을 확인하세요."
    if error.code == 422:
        return "GitHub 검색 조건을 처리하지 못했습니다. 잠시 후 다시 시도하세요."
    return f"GitHub API 요청 실패 (HTTP {error.code})."


def _split_full_name(full_name: str) -> tuple[str, str]:
    parts = full_name.split("/")
    if len(parts) != 2 or not all(re.fullmatch(r"[A-Za-z0-9_.-]+", part) for part in parts):
        raise GitHubError("저장소 이름이 올바르지 않습니다.")
    return parts[0], parts[1]


def _strip_archive_root(name: str) -> str:
    parts = name.replace("\\", "/").split("/", 1)
    return parts[1] if len(parts) == 2 else ""


SKIP_PARTS = {
    ".git",
    ".idea",
    ".vscode",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "coverage",
    "target",
    ".venv",
    "venv",
    "__pycache__",
}
SKIP_NAMES = {
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "poetry.lock",
    "composer.lock",
    "cargo.lock",
}
TEXT_SUFFIXES = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".mjs",
    ".cjs",
    ".json",
    ".jsonl",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".properties",
    ".env",
    ".sh",
    ".bash",
    ".zsh",
    ".ps1",
    ".md",
    ".txt",
    ".html",
    ".htm",
    ".vue",
    ".svelte",
    ".java",
    ".kt",
    ".go",
    ".rs",
    ".rb",
    ".php",
    ".cs",
    ".ipynb",
}


def _is_candidate_file(path: str, size: int) -> bool:
    if not path or size <= 0 or size > MAX_FILE_BYTES:
        return False
    lowered = path.lower()
    parts = set(lowered.split("/"))
    name = lowered.rsplit("/", 1)[-1]
    if parts & SKIP_PARTS or name in SKIP_NAMES:
        return False
    if name.endswith((".min.js", ".map")):
        return False
    if name == ".env" or name.startswith(".env."):
        return True
    suffix = "." + name.rsplit(".", 1)[-1] if "." in name else ""
    return suffix in TEXT_SUFFIXES or name in {"dockerfile", "makefile"}


def _file_priority(path: str) -> tuple[int, int, str]:
    lowered = path.lower()
    name = lowered.rsplit("/", 1)[-1]
    suspicious = name == ".env" or name.startswith(".env.") or any(
        word in name for word in ("secret", "credential", "config", "setting")
    )
    return (0 if suspicious else 1, lowered.count("/"), lowered)
