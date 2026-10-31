import os
import sqlite3
from pathlib import Path
from .models import Report

def connection():
    path = os.getenv('GUARDIAN_DB', str(Path(__file__).resolve().parents[1] / 'guardian.sqlite3'))
    db = sqlite3.connect(path, timeout=10)
    db.execute('CREATE TABLE IF NOT EXISTS scans (id TEXT PRIMARY KEY, created_at TEXT NOT NULL, report TEXT NOT NULL)')
    return db

def save(report):
    with connection() as db:
        db.execute('INSERT INTO scans VALUES (?, ?, ?)', (report.id, report.created_at, report.model_dump_json()))

def get(scan_id):
    with connection() as db:
        row = db.execute('SELECT report FROM scans WHERE id = ?', (scan_id,)).fetchone()
    return Report.model_validate_json(row[0]) if row else None

def recent():
    with connection() as db:
        rows = db.execute('SELECT report FROM scans ORDER BY created_at DESC LIMIT 50').fetchall()
    return [Report.model_validate_json(row[0]) for row in rows]
