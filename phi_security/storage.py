import json
import os
import sqlite3
from pathlib import Path
from datetime import datetime, timezone

def now(): return datetime.now(timezone.utc).isoformat()

class Store:
    def __init__(self, path):
        if path != ':memory:':
            Path(path).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.db = sqlite3.connect(path, timeout=15)
        if path != ':memory:': os.chmod(path, 0o600)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('CREATE TABLE IF NOT EXISTS entities (kind TEXT, id TEXT, data TEXT NOT NULL, updated TEXT NOT NULL, PRIMARY KEY(kind,id))')
        self.db.execute('CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, data TEXT NOT NULL)')
        self.db.execute('CREATE TABLE IF NOT EXISTS locks (name TEXT PRIMARY KEY, expires REAL)')
        self.db.commit()

    def put(self, kind, data):
        from .privacy import storage_safe
        data = storage_safe(data)
        self.db.execute('INSERT INTO entities VALUES (?,?,?,?) ON CONFLICT(kind,id) DO UPDATE SET data=excluded.data,updated=excluded.updated', (kind, data['id'], json.dumps(data, default=str), now()))

    def get(self, kind, identifier):
        row = self.db.execute('SELECT data FROM entities WHERE kind=? AND id=?', (kind, identifier)).fetchone()
        return json.loads(row[0]) if row else None

    def all(self, kind):
        return [json.loads(r[0]) for r in self.db.execute('SELECT data FROM entities WHERE kind=? ORDER BY id', (kind,))]

    def meta(self, key, value=None):
        if value is not None:
            self.db.execute('INSERT INTO meta VALUES (?,?) ON CONFLICT(key) DO UPDATE SET data=excluded.data', (key, json.dumps(value, default=str)))
            return value
        row = self.db.execute('SELECT data FROM meta WHERE key=?', (key,)).fetchone()
        return json.loads(row[0]) if row else None

    def commit(self): self.db.commit()
    def close(self): self.db.close()

    def prune(self, days):
        """Keep evidence linked to an incident/finding/investigation; expire other history."""
        from datetime import timedelta
        cutoff=(datetime.now(timezone.utc)-timedelta(days=days)).isoformat()
        linked=set()
        for kind in ['findings','incidents','investigations','resources','principals']:
            for row in self.all(kind):linked.update(row.get('evidence',[]))
        for row in self.all('evidence'):
            if row['id'] not in linked and str(row.get('timestamp','')) < cutoff:
                self.db.execute('DELETE FROM entities WHERE kind=? AND id=?',('evidence',row['id']))
        for kind in ['scans','cycles','llm_runs']:
            self.db.execute('DELETE FROM entities WHERE kind=? AND updated<?',(kind,cutoff))
