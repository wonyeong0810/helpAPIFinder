from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import json
import os
from pathlib import Path
import re
import threading
import urllib.parse
from typing import Any

from .db import Database, FindingInput, utc_now
from .github import GitHubClient, GitHubError
from .patterns import scan_text


@dataclass(frozen=True)
class ScanConfig:
    recent_days: int = 14
    max_repositories: int = 10
    max_stars: int = 3
    minimum_beginner_score: int = 6
    max_files_per_repository: int = 250
    candidate_multiplier: int = 3

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "ScanConfig":
        return cls(
            recent_days=_bounded_int(payload.get("recent_days", 14), 1, 30, "최근 일수"),
            max_repositories=_bounded_int(payload.get("max_repositories", 10), 1, 25, "저장소 수"),
        )

    def query(self) -> str:
        cutoff = (datetime.now(UTC) - timedelta(days=self.recent_days)).date().isoformat()
        return f"pushed:>={cutoff} stars:0..{self.max_stars} fork:false archived:false is:public"


class ScanManager:
    def __init__(self, database: Database, fingerprint_key: bytes):
        self.database = database
        self.fingerprint_key = fingerprint_key
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._scheduler_thread: threading.Thread | None = None
        self._scheduler_stop = threading.Event()
        self._schedule_interval_minutes = 0

    @property
    def running(self) -> bool:
        with self._lock:
            return bool(self._thread and self._thread.is_alive())

    def start(self, config: ScanConfig) -> int:
        token = _read_secret("GITHUB_TOKEN", "GITHUB_TOKEN_FILE")
        if not token:
            raise ValueError("GITHUB_TOKEN 또는 GITHUB_TOKEN_FILE을 설정한 뒤 다시 실행하세요.")
        with self._lock:
            if self._thread and self._thread.is_alive():
                raise RuntimeError("이미 검사가 진행 중입니다.")
            scan_id = self.database.create_scan(config.query())
            self._thread = threading.Thread(
                target=self._run,
                args=(scan_id, config, token),
                name=f"keylight-scan-{scan_id}",
                daemon=True,
            )
            self._thread.start()
            return scan_id

    def enable_schedule(self, config: ScanConfig, interval_minutes: int) -> None:
        if interval_minutes < 5:
            raise ValueError("자동 검사 간격은 최소 5분이어야 합니다.")
        with self._lock:
            if self._scheduler_thread and self._scheduler_thread.is_alive():
                return
            self._schedule_interval_minutes = interval_minutes
            self._scheduler_stop.clear()
            self._scheduler_thread = threading.Thread(
                target=self._schedule_loop,
                args=(config, interval_minutes),
                name="keylight-scheduler",
                daemon=True,
            )
            self._scheduler_thread.start()

    def schedule_status(self) -> dict[str, Any]:
        with self._lock:
            enabled = bool(self._scheduler_thread and self._scheduler_thread.is_alive())
            return {
                "enabled": enabled,
                "interval_minutes": self._schedule_interval_minutes if enabled else 0,
            }

    def _schedule_loop(self, config: ScanConfig, interval_minutes: int) -> None:
        while not self._scheduler_stop.is_set():
            try:
                if not self.running:
                    self.start(config)
            except (RuntimeError, ValueError):
                # The latest scan endpoint exposes setup and scan failures. A
                # scheduler must never spin or log credentials on failure.
                pass
            self._scheduler_stop.wait(interval_minutes * 60)

    def _run(self, scan_id: int, config: ScanConfig, token: str) -> None:
        client: GitHubClient | None = None
        counts = {
            "repositories_discovered": 0,
            "repositories_eligible": 0,
            "repositories_scanned": 0,
            "files_scanned": 0,
            "findings_total": 0,
            "findings_new": 0,
        }
        try:
            client = GitHubClient(token)
            candidate_limit = min(config.max_repositories * config.candidate_multiplier, 75)
            repositories = client.search_repositories(config.query(), candidate_limit)
            counts["repositories_discovered"] = len(repositories)
            self.database.update_scan(scan_id, **counts)
            owner_cache: dict[str, dict[str, Any]] = {}
            processed_owners = self.database.processed_owners()

            for repository in repositories:
                if counts["repositories_scanned"] >= config.max_repositories:
                    break
                if repository.get("private") is True or repository.get("visibility") not in (None, "public"):
                    continue
                owner_data = repository.get("owner") or {}
                if owner_data.get("type") != "User":
                    continue
                login = str(owner_data.get("login", ""))
                if not login:
                    continue
                owner_key = login.casefold()
                if owner_key in processed_owners:
                    continue
                user = owner_cache.get(login)
                if user is None:
                    user = client.get_user(login)
                    owner_cache[login] = user
                beginner_score, beginner_signals = _assess_beginner(user, repository)
                if beginner_score < config.minimum_beginner_score:
                    continue

                full_name = str(repository.get("full_name", ""))
                default_branch = str(repository.get("default_branch") or "main")
                counts["repositories_eligible"] += 1
                commit_sha = client.get_commit_sha(full_name, default_branch)
                owner_has_finding = False
                for file_path, text in client.iter_archive_files(
                    full_name,
                    commit_sha,
                    max_files=config.max_files_per_repository,
                ):
                    counts["files_scanned"] += 1
                    for detection in scan_text(text, self.fingerprint_key):
                        owner_has_finding = True
                        counts["findings_total"] += 1
                        file_url = _file_url(full_name, commit_sha, file_path, detection.line_number)
                        finding = FindingInput(
                            provider=detection.provider,
                            label=detection.label,
                            fingerprint=detection.fingerprint,
                            masked_secret=detection.masked_secret,
                            repository=full_name,
                            owner=login,
                            repo_url=str(repository.get("html_url", f"https://github.com/{full_name}")),
                            owner_url=str(owner_data.get("html_url", f"https://github.com/{login}")),
                            beginner_score=beginner_score,
                            beginner_signals=json.dumps(beginner_signals, ensure_ascii=False),
                            file_path=file_path,
                            file_url=file_url,
                            line_number=detection.line_number,
                            commit_sha=commit_sha,
                            evidence=detection.evidence,
                            confidence=detection.confidence,
                        )
                        if self.database.upsert_finding(finding):
                            counts["findings_new"] += 1
                counts["repositories_scanned"] += 1
                self.database.mark_owner_processed(
                    login,
                    finding_detected=owner_has_finding,
                )
                processed_owners.add(owner_key)
                self.database.update_scan(
                    scan_id,
                    **counts,
                    rate_remaining=client.rate_remaining,
                    rate_reset=client.rate_reset,
                )

            self.database.update_scan(
                scan_id,
                status="completed",
                finished_at=utc_now(),
                **counts,
                rate_remaining=client.rate_remaining,
                rate_reset=client.rate_reset,
            )
        except (GitHubError, ValueError) as error:
            self.database.update_scan(
                scan_id,
                status="failed",
                finished_at=utc_now(),
                error_message=str(error)[:300],
                **counts,
                rate_remaining=client.rate_remaining if client else None,
                rate_reset=client.rate_reset if client else None,
            )
        except Exception:
            # Avoid persisting arbitrary exception content: it may contain data
            # obtained while scanning a repository.
            self.database.update_scan(
                scan_id,
                status="failed",
                finished_at=utc_now(),
                error_message="검사 중 예상하지 못한 오류가 발생했습니다.",
                **counts,
            )


def _bounded_int(value: Any, minimum: int, maximum: int, label: str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"{label} 값이 올바르지 않습니다.") from None
    if not minimum <= parsed <= maximum:
        raise ValueError(f"{label}는 {minimum}~{maximum} 범위여야 합니다.")
    return parsed


LEARNING_WORDS = re.compile(
    r"(?:tutorial|practice|learning|learn|study|demo|first|hello|toy|course|"
    r"bootcamp|class|assignment|homework|beginner|starter|연습|공부|과제|실습|입문)",
    re.IGNORECASE,
)


def _assess_beginner(user: dict[str, Any], repository: dict[str, Any]) -> tuple[int, list[str]]:
    """Estimate beginner-like activity from public, explainable metadata.

    This is a prioritization heuristic, not a claim about a person's ability.
    Account age contributes a small amount but is never an eligibility gate.
    """
    score = 0
    signals: list[str] = []

    public_repositories = _optional_int(user.get("public_repos"))
    if public_repositories is not None:
        if public_repositories <= 3:
            score += 3
            signals.append("공개 저장소 3개 이하")
        elif public_repositories <= 10:
            score += 2
            signals.append("공개 저장소 10개 이하")
        elif public_repositories <= 25:
            score += 1
            signals.append("공개 저장소 25개 이하")

    followers = _optional_int(user.get("followers"))
    if followers is not None:
        if followers == 0:
            score += 2
            signals.append("팔로워 없음")
        elif followers <= 5:
            score += 1
            signals.append("팔로워 5명 이하")

    try:
        created = datetime.fromisoformat(str(user["created_at"]).replace("Z", "+00:00"))
    except (KeyError, TypeError, ValueError):
        created = None
    if created is not None:
        account_days = (datetime.now(UTC) - created).days
        if account_days <= 180:
            score += 2
            signals.append("계정 활동 6개월 이내")
        elif account_days <= 730:
            score += 1
            signals.append("계정 활동 2년 이내")

    stars = _optional_int(repository.get("stargazers_count"))
    if stars == 0:
        score += 1
        signals.append("스타 없음")

    forks = _optional_int(repository.get("forks_count"))
    if forks == 0:
        score += 1
        signals.append("포크 없음")

    size_kib = _optional_int(repository.get("size"))
    if size_kib is not None and size_kib <= 2048:
        score += 1
        signals.append("소규모 프로젝트")

    if repository.get("license") is None:
        score += 1
        signals.append("라이선스 미설정")

    searchable = " ".join(
        [
            str(repository.get("name") or ""),
            str(repository.get("description") or ""),
            " ".join(str(topic) for topic in (repository.get("topics") or [])),
        ]
    )
    if LEARNING_WORDS.search(searchable):
        score += 2
        signals.append("학습·연습형 프로젝트")

    return score, signals


def _optional_int(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _read_secret(value_name: str, file_name: str) -> str:
    direct = os.environ.get(value_name, "")
    if direct:
        return direct.rstrip("\r\n")
    secret_path = os.environ.get(file_name, "").strip()
    if not secret_path:
        return ""
    try:
        return Path(secret_path).read_text(encoding="utf-8").rstrip("\r\n")
    except OSError:
        return ""


def _file_url(full_name: str, commit_sha: str, file_path: str, line_number: int) -> str:
    quoted_path = urllib.parse.quote(file_path, safe="/")
    return f"https://github.com/{full_name}/blob/{commit_sha}/{quoted_path}#L{line_number}"
