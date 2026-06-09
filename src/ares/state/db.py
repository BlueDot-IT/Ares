from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator


class StateDB:
    """Small SQLite persistence layer for runtime sessions and tool calls."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
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
            columns = {row["name"] for row in conn.execute("PRAGMA table_info(sessions)").fetchall()}
            if "agent" not in columns:
                conn.execute("ALTER TABLE sessions ADD COLUMN agent TEXT")
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
            # memory_chunks table for long-context retrieval
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
            # Try to create FTS5 virtual table; if unavailable, continue without it
            try:
                conn.execute(
                    """
                    CREATE VIRTUAL TABLE IF NOT EXISTS memory_chunks_fts
                    USING fts5(content, target, tags, content='memory_chunks', content_rowid='id')
                    """
                )
                # Triggers to keep FTS in sync
                conn.execute(
                    """
                    CREATE TRIGGER IF NOT EXISTS memory_chunks_ai AFTER INSERT ON memory_chunks BEGIN
                        INSERT INTO memory_chunks_fts(rowid, content, target, tags)
                        VALUES (new.id, new.content, coalesce(new.target, ''), coalesce(new.tags_json, '[]'));
                    END;
                    """
                )
                conn.execute(
                    """
                    CREATE TRIGGER IF NOT EXISTS memory_chunks_ad AFTER DELETE ON memory_chunks BEGIN
                        INSERT INTO memory_chunks_fts(memory_chunks_fts, rowid, content, target, tags)
                        VALUES ('delete', old.id, old.content, coalesce(old.target, ''), coalesce(old.tags_json, '[]'));
                    END;
                    """
                )
                conn.execute(
                    """
                    CREATE TRIGGER IF NOT EXISTS memory_chunks_au AFTER UPDATE ON memory_chunks BEGIN
                        INSERT INTO memory_chunks_fts(memory_chunks_fts, rowid, content, target, tags)
                        VALUES ('delete', old.id, old.content, coalesce(old.target, ''), coalesce(old.tags_json, '[]'));
                        INSERT INTO memory_chunks_fts(rowid, content, target, tags)
                        VALUES (new.id, new.content, coalesce(new.target, ''), coalesce(new.tags_json, '[]'));
                    END;
                    """
                )
            except sqlite3.OperationalError:
                # FTS5 not available; search will fall back to LIKE
                pass

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

    def list_tool_calls(self, session_id: int) -> list[dict[str, Any]]:
        with self._connection() as conn:
            rows = conn.execute(
                "SELECT * FROM tool_calls WHERE session_id = ? ORDER BY id", (session_id,)
            ).fetchall()
            return [dict(row) for row in rows]

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

    # Memory chunks methods
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
        tags: tuple[str, ...] = (),
        limit: int = 6,
    ) -> list[dict[str, Any]]:
        normalized_tags = {t.lower() for t in tags if t}
        results: list[dict[str, Any]] = []

        with self._connection() as conn:
            # Try FTS5 first
            fts_available = True
            try:
                conn.execute("SELECT 1 FROM memory_chunks_fts LIMIT 1")
            except sqlite3.OperationalError:
                fts_available = False

            if fts_available:
                # Build FTS query
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
                sql += " ORDER BY mc.created_at DESC LIMIT ?"
                params.append(limit)
                rows = conn.execute(sql, params).fetchall()
                for row in rows:
                    chunk = dict(row)
                    chunk["tags"] = json.loads(chunk.pop("tags_json"))
                    if normalized_tags:
                        chunk_tags = {t.lower() for t in chunk["tags"]}
                        if not (chunk_tags & normalized_tags):
                            continue
                    results.append(chunk)
                return results[:limit]

            # Fallback: LIKE search
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
            sql += " ORDER BY created_at DESC LIMIT ?"
            params.append(limit * 3)  # fetch more to allow tag filtering
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
