import json, sqlite3, threading
from pathlib import Path
from typing import Any
from .models import Incident, NetworkEvent

class Storage:
    def __init__(self, path: str = "data/sentiflow.db") -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True); self.path=path; self.lock=threading.RLock(); self._initialize()
    def connect(self):
        db=sqlite3.connect(self.path, timeout=10); db.row_factory=sqlite3.Row; return db
    def _initialize(self):
        with self.connect() as db: db.executescript("""
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY,timestamp TEXT,source_ip TEXT,destination_ip TEXT,source_port INTEGER,destination_port INTEGER,protocol TEXT,bytes_sent INTEGER,bytes_received INTEGER,event_type TEXT,dns_query TEXT,outcome TEXT,source TEXT,simulation INTEGER,scenario_id TEXT,label TEXT);
        CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp DESC);
        CREATE TABLE IF NOT EXISTS incidents (id TEXT PRIMARY KEY,detection_type TEXT,severity TEXT,title TEXT,description TEXT,source_ip TEXT,destination_ip TEXT,evidence TEXT,first_seen TEXT,last_seen TEXT,source TEXT,simulation INTEGER,scenario_id TEXT,status TEXT,created_at TEXT);
        CREATE INDEX IF NOT EXISTS idx_incidents_created ON incidents(created_at DESC);""")
    def add_event(self,event:NetworkEvent):
        row=event.to_dict(); row["simulation"]=int(row["simulation"])
        with self.lock,self.connect() as db: db.execute(f"INSERT OR REPLACE INTO events ({','.join(row)}) VALUES ({','.join('?' for _ in row)})",tuple(row.values()))
    def add_incident(self,incident:Incident):
        row=incident.to_dict(); row["simulation"]=int(row["simulation"]); row["evidence"]=json.dumps(row["evidence"])
        with self.lock,self.connect() as db: db.execute(f"INSERT OR REPLACE INTO incidents ({','.join(row)}) VALUES ({','.join('?' for _ in row)})",tuple(row.values()))
    def list_rows(self,table:str,limit:int=100)->list[dict[str,Any]]:
        if table not in {"events","incidents"}: raise ValueError("Invalid table")
        order="created_at" if table=="incidents" else "timestamp"
        with self.connect() as db: rows=[dict(x) for x in db.execute(f"SELECT * FROM {table} ORDER BY {order} DESC LIMIT ?",(min(limit,1000),))]
        for row in rows:
            row["simulation"]=bool(row["simulation"])
            if table=="incidents": row["evidence"]=json.loads(row["evidence"])
        return rows
    def stats(self):
        with self.connect() as db:
            events=db.execute("SELECT COUNT(*) FROM events").fetchone()[0]; incidents=db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]; opened=db.execute("SELECT COUNT(*) FROM incidents WHERE status='open'").fetchone()[0]
            severities=dict(db.execute("SELECT severity,COUNT(*) FROM incidents GROUP BY severity").fetchall()); detections=dict(db.execute("SELECT detection_type,COUNT(*) FROM incidents GROUP BY detection_type").fetchall())
        return {"events":events,"incidents":incidents,"open_incidents":opened,"severities":severities,"detections":detections}
    def update_status(self,i,status):
        with self.connect() as db: return db.execute("UPDATE incidents SET status=? WHERE id=?",(status,i)).rowcount>0
    def clear(self):
        with self.lock,self.connect() as db: db.execute("DELETE FROM events"); db.execute("DELETE FROM incidents")
