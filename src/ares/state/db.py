from __future__ import annotations

import json
import os
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterable, Iterator

from ares.secure_files import PRIVATE_FILE_MODE, tighten_private_fd

if TYPE_CHECKING:
    from ares.mission.findings import MissionFinding
    from ares.mission.model import MissionRun
    from ares.mission.tasks import MissionTask

MISSION_LIFECYCLE_SCHEMA_VERSION = 3
STATE_SCHEMA_VERSION = 4
MISSION_RECONCILIATION_SUMMARY = (
    "Administratively reconciled after mission finalization repair; "
    "actual task completion time was not recorded."
)


class StateDB:
    """Small SQLite persistence layer for runtime sessions, evidence, and memory."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        fd = os.open(
            self.path,
            os.O_CREAT | os.O_RDWR,
            PRIVATE_FILE_MODE,
        )
        try:
            tighten_private_fd(fd)
        finally:
            os.close(fd)
        try:
            self.path.chmod(PRIVATE_FILE_MODE)
        except PermissionError:
            pass
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        conn = self._connect()
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_schema(self) -> None:
        with self._connection() as conn:
            self._ensure_schema_meta(conn)
            row = conn.execute(
                "SELECT value FROM ares_schema_meta "
                "WHERE key = 'schema_version'"
            ).fetchone()
            try:
                previous_schema_version = int(row["value"]) if row else 0
            except (TypeError, ValueError):
                previous_schema_version = 0
            self._ensure_sessions_schema(conn)
            self._ensure_tool_calls_schema(conn)
            self._ensure_messages_schema(conn)
            self._ensure_hosts_schema(conn)
            self._ensure_services_schema(conn)
            self._ensure_memory_schema(
                conn,
                rebuild_existing=previous_schema_version
                < STATE_SCHEMA_VERSION,
            )
            self._ensure_mission_schema(
                conn,
                migrate_legacy_findings=previous_schema_version
                < MISSION_LIFECYCLE_SCHEMA_VERSION,
            )
            self._ensure_autonomy_schema(conn)
            self._set_schema_version(conn, STATE_SCHEMA_VERSION)

    def _ensure_schema_meta(self, conn: sqlite3.Connection) -> None:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ares_schema_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """
        )
    def _set_schema_version(self, conn: sqlite3.Connection, version: int) -> None:
        conn.execute(
            """
            INSERT INTO ares_schema_meta (key, value)
            VALUES ('schema_version', ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """,
            (str(int(version)),),
        )

    def schema_version(self) -> int:
        with self._connection() as conn:
            row = conn.execute(
                "SELECT value FROM ares_schema_meta WHERE key = 'schema_version'"
            ).fetchone()
            if row is None:
                return 0
            try:
                return int(row["value"])
            except (TypeError, ValueError):
                return 0

    def _columns(self, conn: sqlite3.Connection, table: str) -> set[str]:
        return {row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}

    def _ensure_column(self, conn: sqlite3.Connection, table: str, name: str, ddl: str) -> None:
        if name not in self._columns(conn, table):
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")

    def _ensure_sessions_schema(self, conn: sqlite3.Connection) -> None:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at REAL NOT NULL,
                prompt TEXT NOT NULL,
                target TEXT,
                agent TEXT,
                model TEXT,
                mode TEXT,
                status TEXT NOT NULL DEFAULT 'running'
            )
            """
        )
        self._ensure_column(conn, "sessions", "target", "TEXT")
        self._ensure_column(conn, "sessions", "agent", "TEXT")
        self._ensure_column(conn, "sessions", "model", "TEXT")
        self._ensure_column(conn, "sessions", "mode", "TEXT")
        self._ensure_column(conn, "sessions", "status", "TEXT NOT NULL DEFAULT 'running'")

    def _ensure_tool_calls_schema(self, conn: sqlite3.Connection) -> None:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS tool_calls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL,
                created_at REAL NOT NULL,
                tool TEXT NOT NULL,
                args_json TEXT NOT NULL,
                status TEXT NOT NULL,
                result_json TEXT,
                error TEXT,
                duration_ms INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY(session_id) REFERENCES sessions(id)
            )
            """
        )
        self._ensure_column(conn, "tool_calls", "duration_ms", "INTEGER NOT NULL DEFAULT 0")

    def _ensure_messages_schema(self, conn: sqlite3.Connection) -> None:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL,
                created_at REAL NOT NULL,
                role TEXT NOT NULL,
                content TEXT NOT NULL,
                message_json TEXT,
                FOREIGN KEY(session_id) REFERENCES sessions(id)
            )
            """
        )
        self._ensure_column(conn, "messages", "message_json", "TEXT")

    def _ensure_hosts_schema(self, conn: sqlite3.Connection) -> None:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS hosts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL,
                address TEXT NOT NULL,
                hostname TEXT,
                UNIQUE(session_id, address),
                FOREIGN KEY(session_id) REFERENCES sessions(id)
            )
            """
        )

    def _ensure_services_schema(self, conn: sqlite3.Connection) -> None:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS services (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL,
                host_address TEXT NOT NULL,
                port INTEGER NOT NULL,
                proto TEXT NOT NULL,
                service TEXT,
                product TEXT,
                UNIQUE(session_id, host_address, port, proto),
                FOREIGN KEY(session_id) REFERENCES sessions(id)
            )
            """
        )

    def _ensure_memory_schema(
        self,
        conn: sqlite3.Connection,
        *,
        rebuild_existing: bool,
    ) -> None:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS memory_chunks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER,
                source_type TEXT NOT NULL,
                source_id TEXT,
                target TEXT,
                tags_json TEXT NOT NULL DEFAULT '[]',
                content TEXT NOT NULL,
                created_at REAL NOT NULL
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_memory_chunks_target_created ON memory_chunks(target, created_at DESC)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_memory_chunks_session_created ON memory_chunks(session_id, created_at DESC)"
        )
        try:
            schema_current = self._memory_fts_schema_is_current(conn)
            if not schema_current:
                self._drop_memory_fts(conn)
                self._create_memory_fts(conn)
                rebuild_existing = True
            if rebuild_existing:
                self._rebuild_memory_fts(conn)
            try:
                self._check_memory_fts_integrity(conn)
            except sqlite3.DatabaseError:
                self._rebuild_memory_fts(conn)
                self._check_memory_fts_integrity(conn)
        except sqlite3.OperationalError as exc:
            if "no such module: fts5" not in str(exc).lower():
                raise

    def _memory_fts_schema_is_current(
        self,
        conn: sqlite3.Connection,
    ) -> bool:
        table = conn.execute(
            """
            SELECT sql FROM sqlite_master
            WHERE type = 'table' AND name = 'memory_chunks_fts'
            """
        ).fetchone()
        if table is None:
            return False
        table_sql = "".join(str(table["sql"]).lower().split())
        if (
            "content='memory_chunks'" not in table_sql
            or "content_rowid='id'" not in table_sql
        ):
            return False
        columns = tuple(
            row["name"]
            for row in conn.execute(
                "PRAGMA table_info(memory_chunks_fts)"
            ).fetchall()
        )
        if columns != ("content", "target", "tags_json"):
            return False
        for trigger_name in (
            "memory_chunks_ai",
            "memory_chunks_ad",
            "memory_chunks_au",
        ):
            trigger = conn.execute(
                """
                SELECT sql FROM sqlite_master
                WHERE type = 'trigger' AND name = ?
                """,
                (trigger_name,),
            ).fetchone()
            if trigger is None:
                return False
            normalized_sql = "".join(str(trigger["sql"]).lower().split())
            if "rowid,content,target,tags_json" not in normalized_sql:
                return False
        return True

    def _drop_memory_fts(self, conn: sqlite3.Connection) -> None:
        for trigger_name in (
            "memory_chunks_ai",
            "memory_chunks_ad",
            "memory_chunks_au",
        ):
            conn.execute(f"DROP TRIGGER IF EXISTS {trigger_name}")
        conn.execute("DROP TABLE IF EXISTS memory_chunks_fts")

    def _create_memory_fts(self, conn: sqlite3.Connection) -> None:
        conn.execute(
            """
            CREATE VIRTUAL TABLE memory_chunks_fts
            USING fts5(
                content,
                target,
                tags_json,
                content='memory_chunks',
                content_rowid='id'
            )
            """
        )
        conn.execute(
            """
            CREATE TRIGGER memory_chunks_ai AFTER INSERT ON memory_chunks BEGIN
                INSERT INTO memory_chunks_fts(
                    rowid, content, target, tags_json
                ) VALUES (
                    new.id, new.content, coalesce(new.target, ''),
                    coalesce(new.tags_json, '[]')
                );
            END;
            """
        )
        conn.execute(
            """
            CREATE TRIGGER memory_chunks_ad AFTER DELETE ON memory_chunks BEGIN
                INSERT INTO memory_chunks_fts(
                    memory_chunks_fts, rowid, content, target, tags_json
                ) VALUES (
                    'delete', old.id, old.content, coalesce(old.target, ''),
                    coalesce(old.tags_json, '[]')
                );
            END;
            """
        )
        conn.execute(
            """
            CREATE TRIGGER memory_chunks_au AFTER UPDATE ON memory_chunks BEGIN
                INSERT INTO memory_chunks_fts(
                    memory_chunks_fts, rowid, content, target, tags_json
                ) VALUES (
                    'delete', old.id, old.content, coalesce(old.target, ''),
                    coalesce(old.tags_json, '[]')
                );
                INSERT INTO memory_chunks_fts(
                    rowid, content, target, tags_json
                ) VALUES (
                    new.id, new.content, coalesce(new.target, ''),
                    coalesce(new.tags_json, '[]')
                );
            END;
            """
        )

    def _rebuild_memory_fts(self, conn: sqlite3.Connection) -> None:
        conn.execute("INSERT INTO memory_chunks_fts(memory_chunks_fts) VALUES ('rebuild')")

    def _check_memory_fts_integrity(
        self,
        conn: sqlite3.Connection,
    ) -> None:
        conn.execute(
            """
            INSERT INTO memory_chunks_fts(memory_chunks_fts, rank)
            VALUES ('integrity-check', 1)
            """
        )

    def _ensure_mission_schema(
        self,
        conn: sqlite3.Connection,
        *,
        migrate_legacy_findings: bool,
    ) -> None:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS missions (
                id TEXT PRIMARY KEY,
                created_at REAL NOT NULL,
                profile_id TEXT NOT NULL,
                target TEXT NOT NULL,
                scope_json TEXT NOT NULL,
                status TEXT NOT NULL,
                phase TEXT NOT NULL,
                metadata_json TEXT NOT NULL DEFAULT '{}'
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS mission_tasks (
                id TEXT PRIMARY KEY,
                mission_id TEXT NOT NULL,
                created_at REAL NOT NULL,
                role_id TEXT NOT NULL,
                phase TEXT NOT NULL,
                tool_name TEXT,
                toolset TEXT NOT NULL,
                target TEXT NOT NULL,
                description TEXT NOT NULL,
                args_json TEXT NOT NULL DEFAULT '{}',
                depends_on_json TEXT NOT NULL DEFAULT '[]',
                status TEXT NOT NULL,
                block_reason TEXT,
                FOREIGN KEY(mission_id) REFERENCES missions(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS mission_findings (
                id TEXT PRIMARY KEY,
                mission_id TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                state TEXT NOT NULL,
                affected_component TEXT,
                evidence_chunk_ids_json TEXT NOT NULL DEFAULT '[]',
                confidence REAL NOT NULL DEFAULT 0,
                validator_note TEXT,
                recommendation TEXT,
                redacted TEXT,
                FOREIGN KEY(mission_id) REFERENCES missions(id)
            )
            """
        )
        self._ensure_column(
            conn, "mission_tasks", "supporting_evidence_tool_call_ids_json",
            "TEXT NOT NULL DEFAULT '[]'",
        )
        self._ensure_column(
            conn, "mission_tasks", "approval_receipt_id",
            "TEXT NOT NULL DEFAULT ''",
        )
        self._ensure_column(conn, "mission_findings", "redacted", "TEXT")
        self._ensure_column(
            conn, "mission_findings", "evidence_tool_call_ids_json",
            "TEXT NOT NULL DEFAULT '[]'",
        )
        self._ensure_column(
            conn, "mission_findings",
            "contradictory_evidence_tool_call_ids_json",
            "TEXT NOT NULL DEFAULT '[]'",
        )
        self._ensure_column(
            conn, "mission_findings", "reproduction_steps_json",
            "TEXT NOT NULL DEFAULT '[]'",
        )
        self._ensure_column(
            conn, "mission_findings", "confidence_rationale", "TEXT",
        )
        self._ensure_column(
            conn, "mission_findings", "severity_rationale", "TEXT",
        )
        self._ensure_column(
            conn, "mission_findings", "contradiction_resolution",
            "TEXT NOT NULL DEFAULT ''",
        )
        self._ensure_column(
            conn, "mission_findings", "version_only",
            "INTEGER NOT NULL DEFAULT 0",
        )
        # Legacy "validated" rows lack the provenance required to claim safe
        # validation. Migrate them conservatively into the unresolved
        # lifecycle instead of grandfathering an unsupported conclusion.
        if migrate_legacy_findings:
            conn.execute(
                """
                UPDATE mission_findings
                SET state = 'hypothesized'
                WHERE state IN ('hypothesis', 'validated', 'reported')
                """
            )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS mission_operator_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mission_id TEXT NOT NULL,
                task_id TEXT,
                role_id TEXT NOT NULL,
                session_id INTEGER,
                started_at REAL NOT NULL,
                finished_at REAL,
                status TEXT NOT NULL,
                summary TEXT,
                FOREIGN KEY(mission_id) REFERENCES missions(id),
                FOREIGN KEY(session_id) REFERENCES sessions(id)
            )
            """
        )

    def _ensure_autonomy_schema(self, conn: sqlite3.Connection) -> None:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS attack_surface_nodes (
                id TEXT PRIMARY KEY,
                mission_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                node_key TEXT NOT NULL,
                label TEXT NOT NULL,
                attributes_json TEXT NOT NULL DEFAULT '{}',
                evidence_tool_call_ids_json TEXT NOT NULL DEFAULT '[]',
                first_seen REAL NOT NULL,
                last_seen REAL NOT NULL,
                UNIQUE(mission_id, kind, node_key),
                FOREIGN KEY(mission_id) REFERENCES missions(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS attack_surface_edges (
                id TEXT PRIMARY KEY,
                mission_id TEXT NOT NULL,
                source_node_id TEXT NOT NULL,
                target_node_id TEXT NOT NULL,
                relationship TEXT NOT NULL,
                attributes_json TEXT NOT NULL DEFAULT '{}',
                evidence_tool_call_ids_json TEXT NOT NULL DEFAULT '[]',
                first_seen REAL NOT NULL,
                last_seen REAL NOT NULL,
                UNIQUE(mission_id, source_node_id, target_node_id, relationship),
                FOREIGN KEY(mission_id) REFERENCES missions(id),
                FOREIGN KEY(source_node_id) REFERENCES attack_surface_nodes(id),
                FOREIGN KEY(target_node_id) REFERENCES attack_surface_nodes(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS mission_coverage (
                id TEXT PRIMARY KEY,
                mission_id TEXT NOT NULL,
                subject_node_id TEXT NOT NULL,
                capability TEXT NOT NULL,
                required INTEGER NOT NULL DEFAULT 1,
                status TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                evidence_tool_call_ids_json TEXT NOT NULL DEFAULT '[]',
                last_error TEXT,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL,
                UNIQUE(mission_id, subject_node_id, capability),
                FOREIGN KEY(mission_id) REFERENCES missions(id),
                FOREIGN KEY(subject_node_id) REFERENCES attack_surface_nodes(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS mission_planner_cycles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mission_id TEXT NOT NULL,
                session_id INTEGER,
                cycle INTEGER NOT NULL,
                created_at REAL NOT NULL,
                snapshot_json TEXT NOT NULL,
                proposal_json TEXT NOT NULL,
                decision_json TEXT NOT NULL,
                UNIQUE(mission_id, cycle),
                FOREIGN KEY(mission_id) REFERENCES missions(id),
                FOREIGN KEY(session_id) REFERENCES sessions(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS mission_recovery_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mission_id TEXT NOT NULL,
                coverage_id TEXT NOT NULL,
                original_tool_call_id INTEGER,
                recovery_tool_call_id INTEGER,
                strategy TEXT NOT NULL,
                status TEXT NOT NULL,
                reason TEXT,
                created_at REAL NOT NULL,
                UNIQUE(mission_id, coverage_id),
                FOREIGN KEY(mission_id) REFERENCES missions(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS mission_approval_receipts (
                id TEXT PRIMARY KEY,
                mission_id TEXT NOT NULL,
                task_id TEXT NOT NULL,
                task_digest TEXT NOT NULL,
                source TEXT NOT NULL,
                approver TEXT NOT NULL,
                approved_at REAL NOT NULL,
                expires_at REAL,
                used_at REAL,
                FOREIGN KEY(mission_id) REFERENCES missions(id)
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_attack_nodes_mission_kind "
            "ON attack_surface_nodes(mission_id, kind)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_coverage_mission_status "
            "ON mission_coverage(mission_id, status)"
        )

    def create_session(
        self,
        *,
        prompt: str,
        target: str | None,
        agent: str | None = None,
        model: str | None = None,
        mode: str | None = None,
    ) -> int:
        with self._connection() as conn:
            cur = conn.execute(
                """
                INSERT INTO sessions (created_at, prompt, target, agent, model, mode, status)
                VALUES (?, ?, ?, ?, ?, ?, 'running')
                """,
                (time.time(), prompt, target, agent, model, mode),
            )
            return int(cur.lastrowid)

    def finish_session(self, session_id: int, status: str) -> None:
        with self._connection() as conn:
            conn.execute("UPDATE sessions SET status = ? WHERE id = ?", (status, session_id))

    def record_tool_call(
        self,
        session_id: int,
        tool: str | None = None,
        args: dict[str, Any] | None = None,
        status: str = "ok",
        result: Any = None,
        error: str = "",
        duration_ms: int = 0,
        tool_name: str | None = None,
    ) -> int:
        with self._connection() as conn:
            cur = conn.execute(
                """
                INSERT INTO tool_calls (
                    session_id, created_at, tool, args_json, status, result_json, error, duration_ms
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    time.time(),
                    tool or tool_name or "unknown",
                    json.dumps(args or {}, sort_keys=True),
                    status,
                    json.dumps(result, sort_keys=True) if result is not None else None,
                    error or None,
                    int(duration_ms),
                ),
            )
            return int(cur.lastrowid)

    def record_message(
        self,
        session_id: int,
        role: str,
        content: str,
        message: dict[str, Any] | None = None,
    ) -> int:
        with self._connection() as conn:
            cur = conn.execute(
                """
                INSERT INTO messages (session_id, created_at, role, content, message_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    time.time(),
                    role,
                    content,
                    json.dumps(message, sort_keys=True) if message is not None else None,
                ),
            )
            return int(cur.lastrowid)

    def list_sessions(self) -> list[dict[str, Any]]:
        with self._connection() as conn:
            rows = conn.execute("SELECT * FROM sessions ORDER BY id").fetchall()
            return [dict(row) for row in rows]

    def get_session(self, session_id: int) -> dict[str, Any] | None:
        with self._connection() as conn:
            row = conn.execute("SELECT * FROM sessions WHERE id = ?", (session_id,)).fetchone()
            return dict(row) if row is not None else None

    def list_tool_calls(self, session_id: int) -> list[dict[str, Any]]:
        with self._connection() as conn:
            rows = conn.execute(
                "SELECT * FROM tool_calls WHERE session_id = ? ORDER BY id", (session_id,)
            ).fetchall()
            return [dict(row) for row in rows]

    def mission_owns_tool_call(
        self, mission_id: str, tool_call_id: int
    ) -> bool:
        return self.get_mission_tool_call(mission_id, tool_call_id) is not None

    def get_mission_tool_call(
        self, mission_id: str, tool_call_id: int
    ) -> dict[str, Any] | None:
        with self._connection() as conn:
            row = conn.execute(
                """
                SELECT tc.*
                FROM tool_calls tc
                JOIN mission_operator_runs mor ON mor.session_id = tc.session_id
                WHERE mor.mission_id = ? AND tc.id = ?
                  AND tc.created_at >= mor.started_at
                  AND (
                    mor.finished_at IS NULL
                    OR tc.created_at <= mor.finished_at
                  )
                LIMIT 1
                """,
                (mission_id, int(tool_call_id)),
            ).fetchone()
            return dict(row) if row is not None else None

    def list_messages(self, session_id: int) -> list[dict[str, Any]]:
        with self._connection() as conn:
            rows = conn.execute(
                "SELECT * FROM messages WHERE session_id = ? ORDER BY id", (session_id,)
            ).fetchall()
            return [dict(row) for row in rows]

    def record_host(self, session_id: int, address: str, hostname: str | None = None) -> None:
        self.upsert_host(session_id=session_id, address=address, hostname=hostname)

    def record_service(
        self,
        session_id: int,
        host_address: str,
        *,
        port: int,
        protocol: str = "tcp",
        state: str | None = None,
        service: str | None = None,
        product: str | None = None,
    ) -> None:
        self.upsert_service(
            session_id=session_id,
            host_address=host_address,
            port=port,
            proto=protocol,
            service=service or state,
            product=product,
        )

    def upsert_host(self, *, session_id: int, address: str, hostname: str | None = None) -> None:
        with self._connection() as conn:
            conn.execute(
                """
                INSERT INTO hosts (session_id, address, hostname)
                VALUES (?, ?, ?)
                ON CONFLICT(session_id, address) DO UPDATE SET hostname = COALESCE(excluded.hostname, hosts.hostname)
                """,
                (session_id, address, hostname),
            )

    def upsert_service(
        self,
        *,
        session_id: int,
        host_address: str,
        port: int,
        proto: str,
        service: str | None = None,
        product: str | None = None,
    ) -> None:
        with self._connection() as conn:
            conn.execute(
                """
                INSERT INTO services (session_id, host_address, port, proto, service, product)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(session_id, host_address, port, proto)
                DO UPDATE SET service = excluded.service, product = excluded.product
                """,
                (session_id, host_address, int(port), proto, service, product),
            )

    def list_hosts(self, session_id: int) -> list[dict[str, Any]]:
        with self._connection() as conn:
            rows = conn.execute(
                "SELECT * FROM hosts WHERE session_id = ? ORDER BY id", (session_id,)
            ).fetchall()
            return [dict(row) for row in rows]

    def list_services(self, session_id: int) -> list[dict[str, Any]]:
        with self._connection() as conn:
            rows = conn.execute(
                "SELECT * FROM services WHERE session_id = ? ORDER BY port, proto", (session_id,)
            ).fetchall()
            return [dict(row) for row in rows]

    def has_successful_tool_call(self, *, session_id: int, tool: str, args: dict[str, Any]) -> bool:
        args_json = json.dumps(args or {}, sort_keys=True)
        with self._connection() as conn:
            row = conn.execute(
                """
                SELECT id FROM tool_calls
                WHERE session_id = ? AND tool = ? AND args_json = ? AND status = 'ok'
                LIMIT 1
                """,
                (session_id, tool, args_json),
            ).fetchone()
            return row is not None

    def add_memory_chunk(
        self,
        *,
        session_id: int | None,
        source_type: str,
        source_id: str | None,
        target: str | None,
        tags: list[str] | tuple[str, ...],
        content: str,
    ) -> int:
        with self._connection() as conn:
            cur = conn.execute(
                """
                INSERT INTO memory_chunks (session_id, source_type, source_id, target, tags_json, content, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id if session_id is not None else None,
                    source_type,
                    source_id,
                    target,
                    json.dumps(list(tags), sort_keys=True),
                    content,
                    time.time(),
                ),
            )
            return int(cur.lastrowid)

    def search_memory_chunks(
        self,
        *,
        query: str,
        target: str | None = None,
        session_id: int | None = None,
        tags: tuple[str, ...] = (),
        limit: int = 6,
    ) -> list[dict[str, Any]]:
        normalized_tags = {t.lower() for t in tags if t}
        results: list[dict[str, Any]] = []

        with self._connection() as conn:
            fts_available = True
            try:
                conn.execute("SELECT 1 FROM memory_chunks_fts LIMIT 1")
            except sqlite3.OperationalError:
                fts_available = False

            if fts_available:
                fts_query = query.strip()
                if not fts_query:
                    return []
                sql = """
                    SELECT mc.id, mc.session_id, mc.source_type, mc.source_id, mc.target,
                           mc.tags_json, mc.content, mc.created_at
                    FROM memory_chunks mc
                    JOIN memory_chunks_fts fts ON mc.id = fts.rowid
                    WHERE memory_chunks_fts MATCH ?
                """
                params: list[Any] = [fts_query]
                if target:
                    sql += " AND mc.target = ?"
                    params.append(target)
                if session_id is not None:
                    sql += " AND mc.session_id = ?"
                    params.append(session_id)
                sql += " ORDER BY mc.created_at DESC LIMIT ?"
                params.append(limit)
                try:
                    rows = conn.execute(sql, params).fetchall()
                except sqlite3.OperationalError:
                    rows = []
                for row in rows:
                    chunk = dict(row)
                    chunk["tags"] = json.loads(chunk.pop("tags_json"))
                    if normalized_tags:
                        chunk_tags = {t.lower() for t in chunk["tags"]}
                        if not (chunk_tags & normalized_tags):
                            continue
                    results.append(chunk)
                if results:
                    return results[:limit]

            like_query = f"%{query.strip()}%"
            sql = """
                SELECT id, session_id, source_type, source_id, target, tags_json, content, created_at
                FROM memory_chunks
                WHERE content LIKE ?
            """
            params = [like_query]
            if target:
                sql += " AND target = ?"
                params.append(target)
            if session_id is not None:
                sql += " AND session_id = ?"
                params.append(session_id)
            sql += " ORDER BY created_at DESC LIMIT ?"
            params.append(limit * 3)
            rows = conn.execute(sql, params).fetchall()
            for row in rows:
                chunk = dict(row)
                chunk["tags"] = json.loads(chunk.pop("tags_json"))
                if normalized_tags:
                    chunk_tags = {t.lower() for t in chunk["tags"]}
                    if not (chunk_tags & normalized_tags):
                        continue
                results.append(chunk)
                if len(results) >= limit:
                    break
            return results[:limit]

    def create_mission(self, mission: MissionRun) -> None:
        scope_data = {
            "target": mission.scope.target,
            "allowed_paths": mission.scope.allowed_paths,
            "forbidden_paths": mission.scope.forbidden_paths,
            "allowed_hosts": mission.scope.allowed_hosts,
            "forbidden_actions": mission.scope.forbidden_actions,
            "max_risk": mission.scope.max_risk,
        }
        with self._connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO missions (
                    id, created_at, profile_id, target, scope_json, status, phase, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    mission.id,
                    time.time(),
                    mission.profile_id,
                    mission.scope.target,
                    json.dumps(scope_data),
                    mission.status.value if hasattr(mission.status, "value") else str(mission.status),
                    mission.phase.value if hasattr(mission.phase, "value") else str(mission.phase),
                    json.dumps(mission.metadata),
                ),
            )

    def get_mission(self, mission_id: str) -> dict[str, Any] | None:
        with self._connection() as conn:
            row = conn.execute("SELECT * FROM missions WHERE id = ?", (mission_id,)).fetchone()
            if row is None:
                return None
            res = dict(row)
            res["scope"] = json.loads(res.pop("scope_json"))
            res["metadata"] = json.loads(res.pop("metadata_json"))
            return res

    def list_missions(self) -> list[dict[str, Any]]:
        with self._connection() as conn:
            rows = conn.execute("SELECT * FROM missions ORDER BY created_at").fetchall()
            results = []
            for row in rows:
                res = dict(row)
                res["scope"] = json.loads(res.pop("scope_json"))
                res["metadata"] = json.loads(res.pop("metadata_json"))
                results.append(res)
            return results

    def update_mission_status(self, mission_id: str, status: str, phase: str | None = None) -> None:
        with self._connection() as conn:
            if phase is not None:
                conn.execute(
                    "UPDATE missions SET status = ?, phase = ? WHERE id = ?",
                    (status, phase, mission_id),
                )
            else:
                conn.execute(
                    "UPDATE missions SET status = ? WHERE id = ?",
                    (status, mission_id),
                )

    def record_mission_task(self, task: MissionTask) -> None:
        with self._connection() as conn:
            existing = conn.execute(
                "SELECT mission_id FROM mission_tasks WHERE id = ?",
                (task.id,),
            ).fetchone()
            if (
                existing is not None
                and existing["mission_id"] != task.mission_id
            ):
                raise ValueError(
                    f"mission task id {task.id!r} is already owned by "
                    f"mission {existing['mission_id']}"
                )
            conn.execute(
                """
                INSERT INTO mission_tasks (
                    id, mission_id, created_at, role_id, phase, tool_name, toolset, target, description,
                    args_json, depends_on_json, status, block_reason,
                    supporting_evidence_tool_call_ids_json, approval_receipt_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    role_id = excluded.role_id,
                    phase = excluded.phase,
                    tool_name = excluded.tool_name,
                    toolset = excluded.toolset,
                    target = excluded.target,
                    description = excluded.description,
                    args_json = excluded.args_json,
                    depends_on_json = excluded.depends_on_json,
                    status = excluded.status,
                    block_reason = excluded.block_reason,
                    supporting_evidence_tool_call_ids_json =
                        excluded.supporting_evidence_tool_call_ids_json,
                    approval_receipt_id = excluded.approval_receipt_id
                WHERE mission_tasks.mission_id = excluded.mission_id
                """,
                (
                    task.id,
                    task.mission_id,
                    time.time(),
                    task.role_id,
                    task.phase,
                    task.tool_name,
                    task.toolset,
                    task.target,
                    task.description,
                    json.dumps(task.args),
                    json.dumps(task.depends_on),
                    task.status.value if hasattr(task.status, "value") else str(task.status),
                    task.block_reason,
                    json.dumps(task.supporting_evidence_tool_call_ids),
                    task.approval_receipt_id,
                ),
            )

    def update_mission_task_status(self, task_id: str, status: str, block_reason: str = "") -> None:
        with self._connection() as conn:
            conn.execute(
                "UPDATE mission_tasks SET status = ?, block_reason = ? WHERE id = ?",
                (status, block_reason, task_id),
            )

    def list_mission_tasks(self, mission_id: str) -> list[dict[str, Any]]:
        with self._connection() as conn:
            rows = conn.execute(
                "SELECT * FROM mission_tasks WHERE mission_id = ? ORDER BY created_at",
                (mission_id,),
            ).fetchall()
            results = []
            for row in rows:
                res = dict(row)
                res["args"] = json.loads(res.pop("args_json"))
                res["depends_on"] = json.loads(res.pop("depends_on_json"))
                res["supporting_evidence_tool_call_ids"] = json.loads(
                    res.pop("supporting_evidence_tool_call_ids_json") or "[]"
                )
                res["approval_receipt_id"] = (
                    res.get("approval_receipt_id") or ""
                )
                results.append(res)
            return results

    def record_mission_finding(self, finding: MissionFinding) -> None:
        with self._connection() as conn:
            existing = conn.execute(
                "SELECT mission_id FROM mission_findings WHERE id = ?",
                (finding.id,),
            ).fetchone()
            if (
                existing is not None
                and existing["mission_id"] != finding.mission_id
            ):
                raise ValueError(
                    f"mission finding id {finding.id!r} is already owned by "
                    f"mission {existing['mission_id']}"
                )
            conn.execute(
                """
                INSERT INTO mission_findings (
                    id, mission_id, title, severity, state, affected_component,
                    evidence_chunk_ids_json, confidence, validator_note,
                    recommendation, redacted, evidence_tool_call_ids_json,
                    contradictory_evidence_tool_call_ids_json,
                    reproduction_steps_json, confidence_rationale,
                    severity_rationale, contradiction_resolution, version_only
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    title = excluded.title,
                    severity = excluded.severity,
                    state = excluded.state,
                    affected_component = excluded.affected_component,
                    evidence_chunk_ids_json = excluded.evidence_chunk_ids_json,
                    confidence = excluded.confidence,
                    validator_note = excluded.validator_note,
                    recommendation = excluded.recommendation,
                    redacted = excluded.redacted,
                    evidence_tool_call_ids_json =
                        excluded.evidence_tool_call_ids_json,
                    contradictory_evidence_tool_call_ids_json =
                        excluded.contradictory_evidence_tool_call_ids_json,
                    reproduction_steps_json = excluded.reproduction_steps_json,
                    confidence_rationale = excluded.confidence_rationale,
                    severity_rationale = excluded.severity_rationale,
                    contradiction_resolution =
                        excluded.contradiction_resolution,
                    version_only = excluded.version_only
                WHERE mission_findings.mission_id = excluded.mission_id
                """,
                (
                    finding.id,
                    finding.mission_id,
                    finding.title,
                    finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
                    finding.state.value if hasattr(finding.state, "value") else str(finding.state),
                    finding.affected_component,
                    json.dumps(finding.evidence_chunk_ids),
                    finding.confidence,
                    finding.validator_note,
                    finding.recommendation,
                    finding.redacted,
                    json.dumps(finding.evidence_tool_call_ids),
                    json.dumps(finding.contradictory_evidence_tool_call_ids),
                    json.dumps(finding.reproduction_steps),
                    finding.confidence_rationale,
                    finding.severity_rationale,
                    finding.contradiction_resolution,
                    int(finding.version_only),
                ),
            )

    def list_mission_findings(self, mission_id: str) -> list[dict[str, Any]]:
        with self._connection() as conn:
            rows = conn.execute(
                "SELECT * FROM mission_findings WHERE mission_id = ?",
                (mission_id,),
            ).fetchall()
            results = []
            for row in rows:
                res = dict(row)
                res["evidence_chunk_ids"] = json.loads(res.pop("evidence_chunk_ids_json"))
                res["evidence_tool_call_ids"] = json.loads(
                    res.pop("evidence_tool_call_ids_json") or "[]"
                )
                res["contradictory_evidence_tool_call_ids"] = json.loads(
                    res.pop("contradictory_evidence_tool_call_ids_json") or "[]"
                )
                res["reproduction_steps"] = json.loads(
                    res.pop("reproduction_steps_json") or "[]"
                )
                res["version_only"] = bool(res["version_only"])
                results.append(res)
            return results

    def record_recovery_attempt(
        self,
        *,
        mission_id: str,
        coverage_id: str,
        original_tool_call_id: int | None,
        recovery_tool_call_id: int | None,
        strategy: str,
        status: str,
        reason: str = "",
    ) -> int:
        with self._connection() as conn:
            cur = conn.execute(
                """
                INSERT INTO mission_recovery_attempts (
                    mission_id, coverage_id, original_tool_call_id,
                    recovery_tool_call_id, strategy, status, reason, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(mission_id, coverage_id) DO NOTHING
                """,
                (
                    mission_id, coverage_id, original_tool_call_id,
                    recovery_tool_call_id, strategy, status, reason, time.time(),
                ),
            )
            return int(cur.lastrowid) if cur.rowcount == 1 else 0

    def update_recovery_attempt(
        self,
        attempt_id: int,
        *,
        recovery_tool_call_id: int | None,
        status: str,
        reason: str = "",
    ) -> None:
        with self._connection() as conn:
            conn.execute(
                """
                UPDATE mission_recovery_attempts
                SET recovery_tool_call_id = ?, status = ?, reason = ?
                WHERE id = ?
                """,
                (
                    recovery_tool_call_id,
                    status,
                    reason,
                    int(attempt_id),
                ),
            )

    def list_recovery_attempts(self, mission_id: str) -> list[dict[str, Any]]:
        with self._connection() as conn:
            rows = conn.execute(
                """
                SELECT * FROM mission_recovery_attempts
                WHERE mission_id = ? ORDER BY id
                """,
                (mission_id,),
            ).fetchall()
            return [dict(row) for row in rows]

    def record_approval_receipt(
        self,
        *,
        receipt_id: str,
        mission_id: str,
        task_id: str,
        task_digest: str,
        source: str,
        approver: str,
        approved_at: float,
        expires_at: float | None = None,
    ) -> None:
        with self._connection() as conn:
            conn.execute(
                """
                INSERT INTO mission_approval_receipts (
                    id, mission_id, task_id, task_digest, source, approver,
                    approved_at, expires_at, used_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)
                """,
                (
                    receipt_id, mission_id, task_id, task_digest, source,
                    approver, approved_at, expires_at,
                ),
            )

    def get_approval_receipt(self, receipt_id: str) -> dict[str, Any] | None:
        with self._connection() as conn:
            row = conn.execute(
                "SELECT * FROM mission_approval_receipts WHERE id = ?",
                (receipt_id,),
            ).fetchone()
            return dict(row) if row is not None else None

    def consume_approval_receipt(self, receipt_id: str) -> bool:
        now = time.time()
        with self._connection() as conn:
            cur = conn.execute(
                """
                UPDATE mission_approval_receipts SET used_at = ?
                WHERE id = ?
                  AND used_at IS NULL
                  AND (expires_at IS NULL OR expires_at > ?)
                """,
                (now, receipt_id, now),
            )
            return cur.rowcount == 1

    def record_mission_operator_run(
        self,
        *,
        mission_id: str,
        task_id: str | None,
        role_id: str,
        session_id: int | None,
        status: str,
        summary: str = "",
    ) -> int:
        with self._connection() as conn:
            cur = conn.execute(
                """
                INSERT INTO mission_operator_runs (
                    mission_id, task_id, role_id, session_id, started_at, status, summary
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    mission_id,
                    task_id,
                    role_id,
                    session_id,
                    time.time(),
                    status,
                    summary,
                ),
            )
            return int(cur.lastrowid)

    def finish_mission_operator_run(
        self,
        run_id: int,
        *,
        status: str,
        summary: str = "",
    ) -> None:
        with self._connection() as conn:
            conn.execute(
                """
                UPDATE mission_operator_runs
                SET finished_at = ?, status = ?, summary = ?
                WHERE id = ?
                """,
                (time.time(), status, summary, int(run_id)),
            )

    def reconcile_completed_mission_lifecycle(
        self,
        *,
        run_ids: Iterable[int],
        session_ids: Iterable[int],
        apply: bool = False,
    ) -> dict[str, Any]:
        """Reconcile explicitly named, provably stale completed mission rows."""
        expected_run_ids = self._normalize_reconciliation_ids(
            run_ids,
            "run_ids",
        )
        expected_session_ids = self._normalize_reconciliation_ids(
            session_ids,
            "session_ids",
        )
        run_placeholders = ",".join("?" for _ in expected_run_ids)
        session_placeholders = ",".join(
            "?" for _ in expected_session_ids
        )

        with self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE" if apply else "BEGIN")
            rows = conn.execute(
                f"""
                SELECT
                    r.id,
                    r.mission_id,
                    r.task_id,
                    r.session_id,
                    r.status,
                    r.finished_at,
                    r.summary,
                    m.status AS mission_status,
                    t.status AS task_status,
                    s.status AS session_status
                FROM mission_operator_runs AS r
                LEFT JOIN missions AS m ON m.id = r.mission_id
                LEFT JOIN mission_tasks AS t
                  ON t.id = r.task_id AND t.mission_id = r.mission_id
                LEFT JOIN sessions AS s ON s.id = r.session_id
                WHERE r.id IN ({run_placeholders})
                ORDER BY r.id
                """,
                expected_run_ids,
            ).fetchall()
            if len(rows) != len(expected_run_ids):
                raise ValueError(
                    "every requested operator run must exist exactly once"
                )

            actual_session_ids = {
                int(row["session_id"])
                for row in rows
                if row["session_id"] is not None
            }
            if actual_session_ids != set(expected_session_ids):
                raise ValueError(
                    "requested sessions must exactly match the operator runs"
                )

            session_runs = conn.execute(
                f"""
                SELECT id, session_id
                FROM mission_operator_runs
                WHERE session_id IN ({session_placeholders})
                ORDER BY id
                """,
                expected_session_ids,
            ).fetchall()
            if {int(row["id"]) for row in session_runs} != set(
                expected_run_ids
            ):
                raise ValueError(
                    "requested sessions contain operator runs outside the "
                    "explicit run allowlist"
                )

            stale_run_ids: list[int] = []
            reconciled_run_ids: list[int] = []
            running_session_ids: set[int] = set()
            for row in rows:
                if row["mission_status"] != "completed":
                    raise ValueError(
                        f"run {row['id']} mission is not completed"
                    )
                if row["task_status"] != "completed":
                    raise ValueError(
                        f"run {row['id']} task is missing or not completed"
                    )
                if row["session_status"] not in {"running", "completed"}:
                    raise ValueError(
                        f"run {row['id']} session is missing or has an "
                        "unexpected status"
                    )
                if row["session_status"] == "running":
                    running_session_ids.add(int(row["session_id"]))

                status = str(row["status"])
                summary = str(row["summary"] or "")
                if (
                    status == "running"
                    and row["finished_at"] is None
                    and summary == ""
                ):
                    stale_run_ids.append(int(row["id"]))
                    continue
                if (
                    status == "completed"
                    and row["finished_at"] is not None
                    and summary == MISSION_RECONCILIATION_SUMMARY
                ):
                    reconciled_run_ids.append(int(row["id"]))
                    continue
                raise ValueError(
                    f"run {row['id']} does not match the stale or "
                    "previously reconciled lifecycle state"
                )

            updated_runs = 0
            updated_sessions = 0
            reconciliation_time: float | None = None
            if apply and stale_run_ids:
                reconciliation_time = time.time()
                stale_placeholders = ",".join(
                    "?" for _ in stale_run_ids
                )
                cursor = conn.execute(
                    f"""
                    UPDATE mission_operator_runs
                    SET finished_at = ?, status = 'completed', summary = ?
                    WHERE id IN ({stale_placeholders})
                      AND status = 'running'
                      AND finished_at IS NULL
                      AND coalesce(summary, '') = ''
                    """,
                    (
                        reconciliation_time,
                        MISSION_RECONCILIATION_SUMMARY,
                        *stale_run_ids,
                    ),
                )
                updated_runs = int(cursor.rowcount)
                if updated_runs != len(stale_run_ids):
                    raise RuntimeError(
                        "operator run state changed during reconciliation"
                    )

            if apply and running_session_ids:
                running_ids = tuple(sorted(running_session_ids))
                running_placeholders = ",".join(
                    "?" for _ in running_ids
                )
                cursor = conn.execute(
                    f"""
                    UPDATE sessions AS s
                    SET status = 'completed'
                    WHERE s.id IN ({running_placeholders})
                      AND s.status = 'running'
                      AND NOT EXISTS (
                          SELECT 1
                          FROM mission_operator_runs AS r
                          WHERE r.session_id = s.id
                            AND (
                                r.status != 'completed'
                                OR r.finished_at IS NULL
                            )
                      )
                    """,
                    running_ids,
                )
                updated_sessions = int(cursor.rowcount)
                if updated_sessions != len(running_ids):
                    raise RuntimeError(
                        "session state changed during reconciliation"
                    )

        return {
            "applied": bool(apply),
            "run_ids": list(expected_run_ids),
            "session_ids": list(expected_session_ids),
            "stale_runs": len(stale_run_ids),
            "already_reconciled_runs": len(reconciled_run_ids),
            "updated_runs": updated_runs,
            "updated_sessions": updated_sessions,
            "finished_at": reconciliation_time,
        }

    def _normalize_reconciliation_ids(
        self,
        values: Iterable[int],
        label: str,
    ) -> tuple[int, ...]:
        normalized = tuple(int(value) for value in values)
        if not normalized:
            raise ValueError(f"{label} must not be empty")
        if any(value <= 0 for value in normalized):
            raise ValueError(f"{label} must contain only positive integers")
        if len(set(normalized)) != len(normalized):
            raise ValueError(f"{label} must not contain duplicates")
        return tuple(sorted(normalized))

    def list_mission_evidence_chunks(
        self,
        mission_id: str,
    ) -> list[dict[str, Any]]:
        with self._connection() as conn:
            rows = conn.execute(
                """
                SELECT DISTINCT mc.*
                FROM memory_chunks AS mc
                JOIN mission_operator_runs AS mor
                  ON mor.session_id = mc.session_id
                WHERE mor.mission_id = ?
                ORDER BY mc.id
                """,
                (mission_id,),
            ).fetchall()
        results = []
        for row in rows:
            value = dict(row)
            value["tags"] = json.loads(value.pop("tags_json"))
            results.append(value)
        return results

    def upsert_attack_surface_node(
        self,
        *,
        node_id: str,
        mission_id: str,
        kind: str,
        node_key: str,
        label: str,
        attributes: dict[str, Any] | None = None,
        evidence_tool_call_ids: list[int] | tuple[int, ...] = (),
    ) -> None:
        now = time.time()
        with self._connection() as conn:
            existing = conn.execute(
                """
                SELECT attributes_json, evidence_tool_call_ids_json, first_seen
                FROM attack_surface_nodes
                WHERE id = ? AND mission_id = ?
                """,
                (node_id, mission_id),
            ).fetchone()
            merged_attributes = dict(attributes or {})
            merged_evidence = {int(value) for value in evidence_tool_call_ids}
            first_seen = now
            if existing is not None:
                merged_attributes = {
                    **json.loads(existing["attributes_json"]),
                    **merged_attributes,
                }
                merged_evidence.update(
                    int(value)
                    for value in json.loads(
                        existing["evidence_tool_call_ids_json"]
                    )
                )
                first_seen = float(existing["first_seen"])
            conn.execute(
                """
                INSERT INTO attack_surface_nodes (
                    id, mission_id, kind, node_key, label, attributes_json,
                    evidence_tool_call_ids_json, first_seen, last_seen
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    label = excluded.label,
                    attributes_json = excluded.attributes_json,
                    evidence_tool_call_ids_json = excluded.evidence_tool_call_ids_json,
                    last_seen = excluded.last_seen
                """,
                (
                    node_id,
                    mission_id,
                    kind,
                    node_key,
                    label,
                    json.dumps(merged_attributes, sort_keys=True),
                    json.dumps(sorted(merged_evidence)),
                    first_seen,
                    now,
                ),
            )

    def upsert_attack_surface_edge(
        self,
        *,
        edge_id: str,
        mission_id: str,
        source_node_id: str,
        target_node_id: str,
        relationship: str,
        attributes: dict[str, Any] | None = None,
        evidence_tool_call_ids: list[int] | tuple[int, ...] = (),
    ) -> None:
        now = time.time()
        with self._connection() as conn:
            existing = conn.execute(
                """
                SELECT attributes_json, evidence_tool_call_ids_json, first_seen
                FROM attack_surface_edges
                WHERE id = ? AND mission_id = ?
                """,
                (edge_id, mission_id),
            ).fetchone()
            merged_attributes = dict(attributes or {})
            merged_evidence = {int(value) for value in evidence_tool_call_ids}
            first_seen = now
            if existing is not None:
                merged_attributes = {
                    **json.loads(existing["attributes_json"]),
                    **merged_attributes,
                }
                merged_evidence.update(
                    int(value)
                    for value in json.loads(
                        existing["evidence_tool_call_ids_json"]
                    )
                )
                first_seen = float(existing["first_seen"])
            conn.execute(
                """
                INSERT INTO attack_surface_edges (
                    id, mission_id, source_node_id, target_node_id,
                    relationship, attributes_json,
                    evidence_tool_call_ids_json, first_seen, last_seen
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    attributes_json = excluded.attributes_json,
                    evidence_tool_call_ids_json = excluded.evidence_tool_call_ids_json,
                    last_seen = excluded.last_seen
                """,
                (
                    edge_id,
                    mission_id,
                    source_node_id,
                    target_node_id,
                    relationship,
                    json.dumps(merged_attributes, sort_keys=True),
                    json.dumps(sorted(merged_evidence)),
                    first_seen,
                    now,
                ),
            )

    def list_attack_surface_nodes(
        self,
        mission_id: str,
        *,
        kind: str | None = None,
    ) -> list[dict[str, Any]]:
        with self._connection() as conn:
            if kind is None:
                rows = conn.execute(
                    """
                    SELECT * FROM attack_surface_nodes
                    WHERE mission_id = ?
                    ORDER BY kind, node_key
                    """,
                    (mission_id,),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT * FROM attack_surface_nodes
                    WHERE mission_id = ? AND kind = ?
                    ORDER BY node_key
                    """,
                    (mission_id, kind),
                ).fetchall()
        results = []
        for row in rows:
            value = dict(row)
            value["attributes"] = json.loads(value.pop("attributes_json"))
            value["evidence_tool_call_ids"] = json.loads(
                value.pop("evidence_tool_call_ids_json")
            )
            results.append(value)
        return results

    def list_attack_surface_edges(self, mission_id: str) -> list[dict[str, Any]]:
        with self._connection() as conn:
            rows = conn.execute(
                """
                SELECT * FROM attack_surface_edges
                WHERE mission_id = ?
                ORDER BY relationship, source_node_id, target_node_id
                """,
                (mission_id,),
            ).fetchall()
        results = []
        for row in rows:
            value = dict(row)
            value["attributes"] = json.loads(value.pop("attributes_json"))
            value["evidence_tool_call_ids"] = json.loads(
                value.pop("evidence_tool_call_ids_json")
            )
            results.append(value)
        return results

    def upsert_mission_coverage(
        self,
        *,
        coverage_id: str,
        mission_id: str,
        subject_node_id: str,
        capability: str,
        required: bool = True,
        status: str = "pending",
    ) -> None:
        now = time.time()
        with self._connection() as conn:
            conn.execute(
                """
                INSERT INTO mission_coverage (
                    id, mission_id, subject_node_id, capability, required,
                    status, attempts, evidence_tool_call_ids_json,
                    last_error, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, 0, '[]', NULL, ?, ?)
                ON CONFLICT(mission_id, subject_node_id, capability)
                DO UPDATE SET required = MAX(mission_coverage.required, excluded.required)
                """,
                (
                    coverage_id,
                    mission_id,
                    subject_node_id,
                    capability,
                    1 if required else 0,
                    status,
                    now,
                    now,
                ),
            )

    def update_mission_coverage(
        self,
        coverage_id: str,
        *,
        status: str,
        evidence_tool_call_ids: list[int] | tuple[int, ...] = (),
        last_error: str = "",
        increment_attempts: bool = False,
    ) -> None:
        with self._connection() as conn:
            row = conn.execute(
                """
                SELECT evidence_tool_call_ids_json
                FROM mission_coverage WHERE id = ?
                """,
                (coverage_id,),
            ).fetchone()
            if row is None:
                raise KeyError(f"unknown coverage item: {coverage_id}")
            evidence = {
                int(value)
                for value in json.loads(row["evidence_tool_call_ids_json"])
            }
            evidence.update(int(value) for value in evidence_tool_call_ids)
            conn.execute(
                """
                UPDATE mission_coverage
                SET status = ?,
                    attempts = attempts + ?,
                    evidence_tool_call_ids_json = ?,
                    last_error = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    status,
                    1 if increment_attempts else 0,
                    json.dumps(sorted(evidence)),
                    last_error or None,
                    time.time(),
                    coverage_id,
                ),
            )

    def list_mission_coverage(
        self,
        mission_id: str,
        *,
        statuses: tuple[str, ...] = (),
    ) -> list[dict[str, Any]]:
        with self._connection() as conn:
            sql = (
                "SELECT * FROM mission_coverage WHERE mission_id = ?"
            )
            params: list[Any] = [mission_id]
            if statuses:
                placeholders = ",".join("?" for _ in statuses)
                sql += f" AND status IN ({placeholders})"
                params.extend(statuses)
            sql += " ORDER BY created_at, capability, subject_node_id"
            rows = conn.execute(sql, params).fetchall()
        results = []
        for row in rows:
            value = dict(row)
            value["required"] = bool(value["required"])
            value["evidence_tool_call_ids"] = json.loads(
                value.pop("evidence_tool_call_ids_json")
            )
            results.append(value)
        return results

    def record_planner_cycle(
        self,
        *,
        mission_id: str,
        session_id: int | None,
        cycle: int,
        snapshot: dict[str, Any],
        proposal: dict[str, Any],
        decision: dict[str, Any],
    ) -> int:
        with self._connection() as conn:
            cur = conn.execute(
                """
                INSERT INTO mission_planner_cycles (
                    mission_id, session_id, cycle, created_at,
                    snapshot_json, proposal_json, decision_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    mission_id,
                    session_id,
                    int(cycle),
                    time.time(),
                    json.dumps(snapshot, sort_keys=True),
                    json.dumps(proposal, sort_keys=True),
                    json.dumps(decision, sort_keys=True),
                ),
            )
            return int(cur.lastrowid)

    def list_planner_cycles(self, mission_id: str) -> list[dict[str, Any]]:
        with self._connection() as conn:
            rows = conn.execute(
                """
                SELECT * FROM mission_planner_cycles
                WHERE mission_id = ? ORDER BY cycle
                """,
                (mission_id,),
            ).fetchall()
        results = []
        for row in rows:
            value = dict(row)
            value["snapshot"] = json.loads(value.pop("snapshot_json"))
            value["proposal"] = json.loads(value.pop("proposal_json"))
            value["decision"] = json.loads(value.pop("decision_json"))
            results.append(value)
        return results
