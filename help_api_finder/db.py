from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import sqlite3
from typing import Any, Iterator


ALLOWED_STATUSES = {"new", "reviewing", "notified", "resolved", "false_positive"}


def utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class FindingInput:
    provider: str
    label: str
    fingerprint: str
    masked_secret: str
    repository: str
    owner: str
    repo_url: str
    owner_url: str
    beginner_score: int
    beginner_signals: str
    file_path: str
    file_url: str
    line_number: int
    commit_sha: str
    evidence: str
    confidence: str


class Database:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=15)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self.connect() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    provider TEXT NOT NULL,
                    label TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    masked_secret TEXT NOT NULL,
                    repository TEXT NOT NULL,
                    owner TEXT NOT NULL,
                    repo_url TEXT NOT NULL,
                    owner_url TEXT NOT NULL,
                    beginner_score INTEGER NOT NULL DEFAULT 0,
                    beginner_signals TEXT NOT NULL DEFAULT '[]',
                    file_path TEXT NOT NULL,
                    file_url TEXT NOT NULL,
                    line_number INTEGER NOT NULL,
                    commit_sha TEXT NOT NULL,
                    evidence TEXT NOT NULL,
                    confidence TEXT NOT NULL CHECK (confidence IN ('high', 'medium', 'low')),
                    status TEXT NOT NULL DEFAULT 'new'
                        CHECK (status IN ('new', 'reviewing', 'notified', 'resolved', 'false_positive')),
                    first_seen_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL,
                    scan_count INTEGER NOT NULL DEFAULT 1,
                    UNIQUE(repository, file_path, line_number, provider, fingerprint)
                );

                CREATE TABLE IF NOT EXISTS scan_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    status TEXT NOT NULL CHECK (status IN ('running', 'completed', 'failed')),
                    query TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    finished_at TEXT,
                    repositories_discovered INTEGER NOT NULL DEFAULT 0,
                    repositories_eligible INTEGER NOT NULL DEFAULT 0,
                    repositories_scanned INTEGER NOT NULL DEFAULT 0,
                    files_scanned INTEGER NOT NULL DEFAULT 0,
                    findings_total INTEGER NOT NULL DEFAULT 0,
                    findings_new INTEGER NOT NULL DEFAULT 0,
                    rate_remaining INTEGER,
                    rate_reset INTEGER,
                    error_message TEXT
                );

                CREATE TABLE IF NOT EXISTS processed_owners (
                    owner TEXT PRIMARY KEY COLLATE NOCASE,
                    processed_at TEXT NOT NULL,
                    finding_detected INTEGER NOT NULL DEFAULT 0
                        CHECK (finding_detected IN (0, 1))
                );

                CREATE TABLE IF NOT EXISTS processed_repositories (
                    repository TEXT PRIMARY KEY COLLATE NOCASE,
                    owner TEXT NOT NULL COLLATE NOCASE,
                    processed_at TEXT NOT NULL,
                    finding_detected INTEGER NOT NULL DEFAULT 0
                        CHECK (finding_detected IN (0, 1))
                );

                CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
                CREATE INDEX IF NOT EXISTS idx_findings_provider ON findings(provider);
                CREATE INDEX IF NOT EXISTS idx_findings_last_seen ON findings(last_seen_at DESC);
                CREATE INDEX IF NOT EXISTS idx_processed_repositories_owner
                    ON processed_repositories(owner);
                """
            )
            self._migrate_findings(connection)

    @staticmethod
    def _migrate_findings(connection: sqlite3.Connection) -> None:
        """Add explainable beginner scoring to databases created by v0.1."""
        columns = {
            str(row["name"])
            for row in connection.execute("PRAGMA table_info(findings)").fetchall()
        }
        if "beginner_score" not in columns:
            connection.execute(
                "ALTER TABLE findings ADD COLUMN beginner_score INTEGER NOT NULL DEFAULT 0"
            )
        if "beginner_signals" not in columns:
            connection.execute(
                "ALTER TABLE findings ADD COLUMN beginner_signals TEXT NOT NULL DEFAULT '[]'"
            )

    def create_scan(self, query: str) -> int:
        with self.connect() as connection:
            cursor = connection.execute(
                "INSERT INTO scan_runs(status, query, started_at) VALUES ('running', ?, ?)",
                (query, utc_now()),
            )
            return int(cursor.lastrowid)

    def update_scan(self, scan_id: int, **fields: Any) -> None:
        allowed = {
            "status",
            "finished_at",
            "repositories_discovered",
            "repositories_eligible",
            "repositories_scanned",
            "files_scanned",
            "findings_total",
            "findings_new",
            "rate_remaining",
            "rate_reset",
            "error_message",
        }
        values = {key: value for key, value in fields.items() if key in allowed}
        if not values:
            return
        assignments = ", ".join(f"{key} = ?" for key in values)
        with self.connect() as connection:
            connection.execute(
                f"UPDATE scan_runs SET {assignments} WHERE id = ?",  # noqa: S608 - allowlisted names
                (*values.values(), scan_id),
            )

    def latest_scan(self) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM scan_runs ORDER BY id DESC LIMIT 1").fetchone()
            return dict(row) if row else None

    def mark_interrupted_scans(self) -> int:
        """Close scans left running by a process or container restart."""
        with self.connect() as connection:
            cursor = connection.execute(
                """
                UPDATE scan_runs
                SET status = 'failed', finished_at = ?,
                    error_message = '서버 재시작으로 검사가 중단되었습니다.'
                WHERE status = 'running'
                """,
                (utc_now(),),
            )
            return cursor.rowcount

    def upsert_finding(self, finding: FindingInput) -> bool:
        data = asdict(finding)
        now = utc_now()
        columns = ", ".join(data)
        placeholders = ", ".join("?" for _ in data)
        with self.connect() as connection:
            cursor = connection.execute(
                f"""
                INSERT INTO findings ({columns}, first_seen_at, last_seen_at)
                VALUES ({placeholders}, ?, ?)
                ON CONFLICT(repository, file_path, line_number, provider, fingerprint)
                DO UPDATE SET
                    last_seen_at = excluded.last_seen_at,
                    scan_count = findings.scan_count + 1,
                    file_url = excluded.file_url,
                    commit_sha = excluded.commit_sha,
                    evidence = excluded.evidence,
                    beginner_score = excluded.beginner_score,
                    beginner_signals = excluded.beginner_signals
                """,
                (*data.values(), now, now),
            )
            return cursor.rowcount == 1 and connection.execute("SELECT changes()").fetchone()[0] == 1 and self._was_just_inserted(connection, data, now)

    def processed_owners(self) -> set[str]:
        """Return accounts for which at least one repository was processed.

        Owners already present in findings are included for databases created
        before the processed-owner table existed.
        """
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT owner FROM processed_owners
                UNION
                SELECT owner FROM findings
                """
            ).fetchall()
            return {str(row["owner"]).casefold() for row in rows if row["owner"]}

    def owners_with_findings(self) -> set[str]:
        """Return accounts that must be skipped even when they add repositories."""
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT owner FROM processed_owners WHERE finding_detected = 1
                UNION
                SELECT owner FROM findings
                """
            ).fetchall()
            return {str(row["owner"]).casefold() for row in rows if row["owner"]}

    def processed_repositories(self) -> set[str]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT repository FROM processed_repositories"
            ).fetchall()
            return {
                str(row["repository"]).casefold()
                for row in rows
                if row["repository"]
            }

    def mark_owner_processed(self, owner: str, *, finding_detected: bool) -> None:
        owner = owner.strip()
        if not owner or len(owner) > 100:
            raise ValueError("invalid owner")
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO processed_owners(owner, processed_at, finding_detected)
                VALUES (?, ?, ?)
                ON CONFLICT(owner) DO UPDATE SET
                    finding_detected = MAX(processed_owners.finding_detected,
                                           excluded.finding_detected)
                """,
                (owner, utc_now(), int(finding_detected)),
            )

    def mark_repository_processed(
        self,
        repository: str,
        owner: str,
        *,
        finding_detected: bool,
    ) -> None:
        repository = repository.strip()
        owner = owner.strip()
        if not repository or len(repository) > 200 or "/" not in repository:
            raise ValueError("invalid repository")
        if not owner or len(owner) > 100:
            raise ValueError("invalid owner")
        now = utc_now()
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO processed_repositories(
                    repository, owner, processed_at, finding_detected
                ) VALUES (?, ?, ?, ?)
                ON CONFLICT(repository) DO UPDATE SET
                    finding_detected = MAX(processed_repositories.finding_detected,
                                           excluded.finding_detected)
                """,
                (repository, owner, now, int(finding_detected)),
            )
            connection.execute(
                """
                INSERT INTO processed_owners(owner, processed_at, finding_detected)
                VALUES (?, ?, ?)
                ON CONFLICT(owner) DO UPDATE SET
                    finding_detected = MAX(processed_owners.finding_detected,
                                           excluded.finding_detected)
                """,
                (owner, now, int(finding_detected)),
            )

    @staticmethod
    def _was_just_inserted(connection: sqlite3.Connection, data: dict[str, Any], now: str) -> bool:
        row = connection.execute(
            """
            SELECT first_seen_at, scan_count FROM findings
            WHERE repository = ? AND file_path = ? AND line_number = ?
              AND provider = ? AND fingerprint = ?
            """,
            (
                data["repository"],
                data["file_path"],
                data["line_number"],
                data["provider"],
                data["fingerprint"],
            ),
        ).fetchone()
        return bool(row and row["first_seen_at"] == now and row["scan_count"] == 1)

    def list_findings(
        self,
        *,
        status: str = "",
        provider: str = "",
        search: str = "",
        limit: int = 100,
        offset: int = 0,
    ) -> dict[str, Any]:
        clauses: list[str] = []
        parameters: list[Any] = []
        if status and status in ALLOWED_STATUSES:
            clauses.append("status = ?")
            parameters.append(status)
        if provider:
            clauses.append("provider = ?")
            parameters.append(provider)
        if search:
            clauses.append("(repository LIKE ? OR file_path LIKE ? OR owner LIKE ?)")
            term = f"%{search[:100]}%"
            parameters.extend((term, term, term))
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        limit = max(1, min(limit, 250))
        offset = max(0, offset)
        with self.connect() as connection:
            total = connection.execute(
                f"SELECT COUNT(*) FROM findings {where}",  # noqa: S608 - static clauses
                parameters,
            ).fetchone()[0]
            rows = connection.execute(
                f"""
                SELECT id, provider, label, masked_secret, repository, owner,
                       repo_url, owner_url, beginner_score, beginner_signals,
                       file_path, file_url, line_number,
                       commit_sha, evidence, confidence, status, first_seen_at,
                       last_seen_at, scan_count, substr(fingerprint, 1, 12) AS fingerprint
                FROM findings {where}
                ORDER BY CASE status WHEN 'new' THEN 0 WHEN 'reviewing' THEN 1 ELSE 2 END,
                         last_seen_at DESC
                LIMIT ? OFFSET ?
                """,
                (*parameters, limit, offset),
            ).fetchall()
            items = [dict(row) for row in rows]
            for item in items:
                try:
                    signals = json.loads(item["beginner_signals"])
                    item["beginner_signals"] = signals if isinstance(signals, list) else []
                except (TypeError, json.JSONDecodeError):
                    item["beginner_signals"] = []
            return {"items": items, "total": total}

    def update_finding_status(self, finding_id: int, status: str) -> bool:
        if status not in ALLOWED_STATUSES:
            raise ValueError("invalid status")
        with self.connect() as connection:
            cursor = connection.execute(
                "UPDATE findings SET status = ? WHERE id = ?", (status, finding_id)
            )
            return cursor.rowcount == 1

    def summary(self) -> dict[str, Any]:
        with self.connect() as connection:
            total = connection.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
            new = connection.execute("SELECT COUNT(*) FROM findings WHERE status = 'new'").fetchone()[0]
            notified = connection.execute("SELECT COUNT(*) FROM findings WHERE status = 'notified'").fetchone()[0]
            repositories = connection.execute("SELECT COUNT(DISTINCT repository) FROM findings").fetchone()[0]
            providers = [
                dict(row)
                for row in connection.execute(
                    "SELECT provider, COUNT(*) AS count FROM findings GROUP BY provider ORDER BY count DESC"
                ).fetchall()
            ]
            return {
                "total": total,
                "new": new,
                "notified": notified,
                "repositories": repositories,
                "providers": providers,
            }


def load_fingerprint_key(db_path: str | Path) -> bytes:
    configured = os.environ.get("FINDER_FINGERPRINT_KEY", "")
    if configured:
        return configured.encode("utf-8")
    key_path = Path(db_path).with_name("fingerprint.key")
    try:
        return key_path.read_bytes()
    except FileNotFoundError:
        key_path.parent.mkdir(parents=True, exist_ok=True)
        key = os.urandom(32)
        try:
            with key_path.open("xb") as handle:
                handle.write(key)
        except FileExistsError:
            return key_path.read_bytes()
        return key
