import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional
from uuid import uuid4
from .models import Report, ConversationMessage, ConversationSession, FindingCitation

def connection():
    path = os.getenv('GUARDIAN_DB', str(Path(__file__).resolve().parents[1] / 'guardian.sqlite3'))
    db = sqlite3.connect(path, timeout=10)
    db.execute('CREATE TABLE IF NOT EXISTS scans (id TEXT PRIMARY KEY, created_at TEXT NOT NULL, report TEXT NOT NULL)')
    db.execute('''
        CREATE TABLE IF NOT EXISTS conversations (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    ''')
    db.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id TEXT PRIMARY KEY,
            conversation_id TEXT NOT NULL,
            scan_id TEXT NOT NULL,
            role TEXT NOT NULL,
            content TEXT NOT NULL,
            citations TEXT,
            limitations TEXT,
            suggested_followups TEXT,
            provider TEXT NOT NULL,
            model TEXT,
            created_at TEXT NOT NULL
        )
    ''')
    db.execute('CREATE INDEX IF NOT EXISTS idx_messages_scan ON messages(scan_id, conversation_id, created_at)')
    return db

def save(report: Report):
    with connection() as db:
        db.execute('INSERT OR REPLACE INTO scans VALUES (?, ?, ?)', (report.id, report.created_at, report.model_dump_json()))

def get(scan_id: str) -> Optional[Report]:
    with connection() as db:
        row = db.execute('SELECT report FROM scans WHERE id = ?', (scan_id,)).fetchone()
    return Report.model_validate_json(row[0]) if row else None

def recent() -> List[Report]:
    with connection() as db:
        rows = db.execute('SELECT report FROM scans ORDER BY created_at DESC LIMIT 50').fetchall()
    return [Report.model_validate_json(row[0]) for row in rows]

def get_or_create_conversation(scan_id: str, conversation_id: Optional[str] = None) -> ConversationSession:
    now = datetime.now(timezone.utc).isoformat()
    with connection() as db:
        if conversation_id:
            row = db.execute(
                'SELECT id, scan_id, created_at, updated_at FROM conversations WHERE id = ? AND scan_id = ?',
                (conversation_id, scan_id)
            ).fetchone()
            if row:
                cid, sid, c_at, u_at = row
                msgs = list_messages(scan_id, cid)
                return ConversationSession(id=cid, scan_id=sid, messages=msgs, created_at=c_at, updated_at=u_at)

        # Look for most recent conversation for this scan
        row = db.execute(
            'SELECT id, scan_id, created_at, updated_at FROM conversations WHERE scan_id = ? ORDER BY updated_at DESC LIMIT 1',
            (scan_id,)
        ).fetchone()
        if row:
            cid, sid, c_at, u_at = row
            msgs = list_messages(scan_id, cid)
            return ConversationSession(id=cid, scan_id=sid, messages=msgs, created_at=c_at, updated_at=u_at)

        # Create new conversation
        new_id = uuid4().hex[:16]
        db.execute(
            'INSERT INTO conversations (id, scan_id, created_at, updated_at) VALUES (?, ?, ?, ?)',
            (new_id, scan_id, now, now)
        )
        return ConversationSession(id=new_id, scan_id=scan_id, messages=[], created_at=now, updated_at=now)

def new_conversation(scan_id: str) -> ConversationSession:
    now = datetime.now(timezone.utc).isoformat()
    new_id = uuid4().hex[:16]
    with connection() as db:
        db.execute(
            'INSERT INTO conversations (id, scan_id, created_at, updated_at) VALUES (?, ?, ?, ?)',
            (new_id, scan_id, now, now)
        )
    return ConversationSession(id=new_id, scan_id=scan_id, messages=[], created_at=now, updated_at=now)

def list_messages(scan_id: str, conversation_id: str) -> List[ConversationMessage]:
    with connection() as db:
        rows = db.execute(
            'SELECT id, conversation_id, scan_id, role, content, citations, limitations, suggested_followups, provider, model, created_at '
            'FROM messages WHERE scan_id = ? AND conversation_id = ? ORDER BY created_at ASC',
            (scan_id, conversation_id)
        ).fetchall()

    messages = []
    for r in rows:
        citations_data = json.loads(r[5]) if r[5] else []
        citations = [FindingCitation.model_validate(c) for c in citations_data]
        limitations = json.loads(r[6]) if r[6] else []
        suggested = json.loads(r[7]) if r[7] else []
        messages.append(ConversationMessage(
            id=r[0],
            conversation_id=r[1],
            scan_id=r[2],
            role=r[3],
            content=r[4],
            citations=citations,
            limitations=limitations,
            suggested_followups=suggested,
            provider=r[8],
            model=r[9],
            created_at=r[10]
        ))
    return messages

def save_message(
    scan_id: str,
    conversation_id: str,
    role: str,
    content: str,
    citations: Optional[List[FindingCitation]] = None,
    limitations: Optional[List[str]] = None,
    suggested_followups: Optional[List[str]] = None,
    provider: str = 'deterministic',
    model: Optional[str] = None
) -> ConversationMessage:
    now = datetime.now(timezone.utc).isoformat()
    msg_id = uuid4().hex[:16]
    citations_list = citations or []
    limitations_list = limitations or []
    followups_list = suggested_followups or []

    citations_json = json.dumps([c.model_dump() for c in citations_list])
    limitations_json = json.dumps(limitations_list)
    followups_json = json.dumps(followups_list)

    with connection() as db:
        db.execute(
            'INSERT INTO messages (id, conversation_id, scan_id, role, content, citations, limitations, suggested_followups, provider, model, created_at) '
            'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            (msg_id, conversation_id, scan_id, role, content, citations_json, limitations_json, followups_json, provider, model, now)
        )
        db.execute('UPDATE conversations SET updated_at = ? WHERE id = ?', (now, conversation_id))

    return ConversationMessage(
        id=msg_id,
        conversation_id=conversation_id,
        scan_id=scan_id,
        role=role,
        content=content,
        citations=citations_list,
        limitations=limitations_list,
        suggested_followups=followups_list,
        provider=provider,
        model=model,
        created_at=now
    )

def clear_conversation(scan_id: str, conversation_id: Optional[str] = None):
    with connection() as db:
        if conversation_id:
            db.execute('DELETE FROM messages WHERE scan_id = ? AND conversation_id = ?', (scan_id, conversation_id))
            db.execute('DELETE FROM conversations WHERE id = ? AND scan_id = ?', (conversation_id, scan_id))
        else:
            db.execute('DELETE FROM messages WHERE scan_id = ?', (scan_id,))
            db.execute('DELETE FROM conversations WHERE scan_id = ?', (scan_id,))
