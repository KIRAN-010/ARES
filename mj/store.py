"""SQLite state with serialized writes and a hash-linked audit trail.

Audit hashes detect accidental edits; they are NOT protection from an administrator
who can rewrite the entire database. Export and externally anchor hashes for that.
"""
import hashlib
import json
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone


def now():
    return datetime.now(timezone.utc).isoformat()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


class Store:
    def __init__(self, path):
        self.lock = threading.RLock()
        self.db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
            PRAGMA journal_mode=WAL;
            PRAGMA foreign_keys=ON;
            PRAGMA busy_timeout=5000;
            CREATE TABLE IF NOT EXISTS objects (
                id TEXT PRIMARY KEY, kind TEXT NOT NULL, created TEXT NOT NULL, body TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS objects_kind ON objects(kind,created);
            CREATE TABLE IF NOT EXISTS audit (
                seq INTEGER PRIMARY KEY AUTOINCREMENT, created TEXT NOT NULL,
                event TEXT NOT NULL, body TEXT NOT NULL, previous TEXT NOT NULL, hash TEXT NOT NULL
            );
        """)

    @contextmanager
    def transaction(self):
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                yield
                self.db.execute("COMMIT")
            except BaseException:
                self.db.execute("ROLLBACK")
                raise

    def _audit(self, event, body):
        row = self.db.execute("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        previous = row[0] if row else "0" * 64
        created = now()
        encoded = canonical(body)
        digest = hashlib.sha256((previous + created + event + encoded).encode()).hexdigest()
        self.db.execute("INSERT INTO audit(created,event,body,previous,hash) VALUES(?,?,?,?,?)",
                        (created, event, encoded, previous, digest))

    def add(self, kind, body):
        record = dict(body, id=uuid.uuid4().hex, created=now())
        with self.transaction():
            self.db.execute("INSERT INTO objects VALUES(?,?,?,?)",
                            (record["id"], kind, record["created"], canonical(record)))
            self._audit(kind + ".created", record)
        return record

    def get(self, kind, identifier):
        with self.lock:
            row = self.db.execute("SELECT body FROM objects WHERE kind=? AND id=?", (kind, identifier)).fetchone()
        if not row:
            raise KeyError(f"Unknown {kind}: {identifier}")
        return json.loads(row[0])

    def list(self, kind, limit=500):
        with self.lock:
            rows = self.db.execute("SELECT body FROM objects WHERE kind=? ORDER BY rowid DESC LIMIT ?",
                                   (kind, limit)).fetchall()
        return [json.loads(row[0]) for row in rows]

    def update(self, kind, identifier, changes, expected=None):
        with self.transaction():
            record = self.get(kind, identifier)
            if expected and any(record.get(k) != v for k, v in expected.items()):
                raise ValueError("State changed; refresh before retrying")
            record.update(changes)
            self.db.execute("UPDATE objects SET body=? WHERE id=?", (canonical(record), identifier))
            self._audit(kind + ".updated", {"id": identifier, "changes": changes})
        return record

    def audit(self):
        with self.lock:
            return [dict(r) for r in self.db.execute("SELECT * FROM audit ORDER BY seq")]

    def verify(self):
        previous = "0" * 64
        rows = self.audit()
        for row in rows:
            digest = hashlib.sha256((previous + row["created"] + row["event"] + row["body"]).encode()).hexdigest()
            if row["previous"] != previous or row["hash"] != digest:
                return {"valid": False, "broken_at": row["seq"], "entries": len(rows)}
            previous = digest
        return {"valid": True, "entries": len(rows), "head": previous}

    def close(self):
        self.db.close()
