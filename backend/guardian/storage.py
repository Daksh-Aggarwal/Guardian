import json
import os
import secrets
import sqlite3
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import List, Optional, Dict, Set
from uuid import uuid4
from .models import Report, ConversationMessage, ConversationSession, FindingCitation
from .remediation_models import RemediationPlan, VerificationResult

def connection():
    path = os.getenv('GUARDIAN_DB', str(Path(__file__).resolve().parents[1] / 'guardian.sqlite3'))
    db = sqlite3.connect(path, timeout=10)
    db.execute('PRAGMA foreign_keys = ON')
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
    db.execute('''
        CREATE TABLE IF NOT EXISTS remediation_plans (
            plan_id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            plan_json TEXT NOT NULL
        )
    ''')
    db.execute('CREATE INDEX IF NOT EXISTS idx_plans_scan ON remediation_plans(scan_id)')
    db.execute('''
        CREATE TABLE IF NOT EXISTS verification_results (
            plan_id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            verified_at TEXT NOT NULL,
            result_json TEXT NOT NULL
        )
    ''')
    db.execute('''
        CREATE TABLE IF NOT EXISTS github_installations (
            installation_id INTEGER PRIMARY KEY,
            account_login TEXT NOT NULL,
            account_type TEXT NOT NULL,
            account_avatar TEXT,
            repository_selection TEXT,
            installed_at TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1
        )
    ''')
    db.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            last_active TEXT NOT NULL,
            expires_at TEXT NOT NULL
        )
    ''')
    db.execute('''
        CREATE TABLE IF NOT EXISTS session_installations (
            session_id TEXT NOT NULL,
            installation_id INTEGER NOT NULL,
            is_selected INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (session_id, installation_id),
            FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE,
            FOREIGN KEY (installation_id) REFERENCES github_installations(installation_id) ON DELETE CASCADE
        )
    ''')
    db.execute('CREATE INDEX IF NOT EXISTS idx_session_inst_sess ON session_installations(session_id)')
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

def delete_scan(scan_id: str) -> bool:
    with connection() as db:
        row = db.execute('SELECT 1 FROM scans WHERE id = ?', (scan_id,)).fetchone()
        if not row:
            return False
        db.execute('DELETE FROM verification_results WHERE scan_id = ?', (scan_id,))
        db.execute('DELETE FROM remediation_plans WHERE scan_id = ?', (scan_id,))
        db.execute('DELETE FROM messages WHERE scan_id = ?', (scan_id,))
        db.execute('DELETE FROM conversations WHERE scan_id = ?', (scan_id,))
        db.execute('DELETE FROM scans WHERE id = ?', (scan_id,))
        return True

def delete_scans(scan_ids: List[str]) -> List[str]:
    if not scan_ids:
        return []
    with connection() as db:
        placeholders = ','.join('?' for _ in scan_ids)
        rows = db.execute(f'SELECT id FROM scans WHERE id IN ({placeholders})', scan_ids).fetchall()
        existing_ids = [r[0] for r in rows]
        if not existing_ids:
            return []
        ex_placeholders = ','.join('?' for _ in existing_ids)
        db.execute(f'DELETE FROM verification_results WHERE scan_id IN ({ex_placeholders})', existing_ids)
        db.execute(f'DELETE FROM remediation_plans WHERE scan_id IN ({ex_placeholders})', existing_ids)
        db.execute(f'DELETE FROM messages WHERE scan_id IN ({ex_placeholders})', existing_ids)
        db.execute(f'DELETE FROM conversations WHERE scan_id IN ({ex_placeholders})', existing_ids)
        db.execute(f'DELETE FROM scans WHERE id IN ({ex_placeholders})', existing_ids)
        return existing_ids

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

def save_plan(plan: RemediationPlan):
    with connection() as db:
        db.execute(
            'INSERT OR REPLACE INTO remediation_plans (plan_id, scan_id, status, created_at, plan_json) '
            'VALUES (?, ?, ?, ?, ?)',
            (plan.plan_id, plan.scan_id, plan.status, plan.created_at, plan.model_dump_json())
        )

def get_plan(plan_id: str) -> Optional[RemediationPlan]:
    with connection() as db:
        row = db.execute('SELECT plan_json FROM remediation_plans WHERE plan_id = ?', (plan_id,)).fetchone()
    if row:
        return RemediationPlan.model_validate_json(row[0])
    return None

def get_plans_for_scan(scan_id: str) -> List[RemediationPlan]:
    with connection() as db:
        rows = db.execute('SELECT plan_json FROM remediation_plans WHERE scan_id = ? ORDER BY created_at DESC', (scan_id,)).fetchall()
    return [RemediationPlan.model_validate_json(r[0]) for r in rows]

def get_plans_for_project(project_identifier: str) -> List[RemediationPlan]:
    with connection() as db:
        all_scans = db.execute('SELECT id, report FROM scans').fetchall()
        matching_scan_ids = []
        for sid, rep_json in all_scans:
            try:
                rep_data = json.loads(rep_json)
                rep_proj_id = rep_data.get('project_id')
                rep_name = rep_data.get('name')
                if rep_proj_id:
                    if rep_proj_id == project_identifier:
                        matching_scan_ids.append(sid)
                else:
                    if rep_name == project_identifier:
                        matching_scan_ids.append(sid)
            except Exception:
                pass
        if not matching_scan_ids:
            return []
        placeholders = ','.join('?' for _ in matching_scan_ids)
        rows = db.execute(
            f'SELECT plan_json FROM remediation_plans WHERE scan_id IN ({placeholders}) ORDER BY created_at DESC',
            matching_scan_ids
        ).fetchall()
    return [RemediationPlan.model_validate_json(r[0]) for r in rows]

VALID_STATUS_TRANSITIONS: Dict[str, Set[str]] = {
    'proposed': {'approved', 'rejected', 'applying', 'applied', 'failed', 'verified', 'stale'},
    'approved': {'applying', 'applied', 'failed', 'rejected', 'reverted', 'stale'},
    'applying': {'applied', 'failed'},
    'applied': {'reverted', 'verified', 'failed', 'pr_closed'},
    'reverted': {'approved', 'applying', 'applied', 'failed', 'rejected'},
    'pr_closed': {'applied', 'approved', 'rejected'},
    'verified': {'reverted', 'pr_closed'},
    'rejected': set(),
    'failed': {'approved', 'applying', 'applied', 'reverted'},
    'stale': set(),
}

def validate_plan_transition(current_status: str, target_status: str) -> None:
    allowed = VALID_STATUS_TRANSITIONS.get(current_status, set())
    if target_status not in allowed:
        raise ValueError(
            f"Invalid remediation plan lifecycle transition from '{current_status}' to '{target_status}'."
        )

def update_plan_status(plan_id: str, status: str) -> Optional[RemediationPlan]:
    plan = get_plan(plan_id)
    if not plan:
        return None
    if status in {'approved', 'applying', 'applied', 'verified'} and plan.validation_status != 'VERIFIED':
        raise ValueError(f"Cannot {status} remediation plan: validation is {plan.validation_status}. {'; '.join(plan.validation_reasons)}")
    validate_plan_transition(plan.status, status)
    plan.status = status
    save_plan(plan)
    return plan

def save_verification(verification: VerificationResult):
    with connection() as db:
        db.execute(
            'INSERT OR REPLACE INTO verification_results (plan_id, scan_id, verified_at, result_json) '
            'VALUES (?, ?, ?, ?)',
            (verification.plan_id, verification.scan_id, verification.verified_at, verification.model_dump_json())
        )

def get_verification(plan_id: str) -> Optional[VerificationResult]:
    with connection() as db:
        row = db.execute('SELECT result_json FROM verification_results WHERE plan_id = ?', (plan_id,)).fetchone()
    if row:
        return VerificationResult.model_validate_json(row[0])
    return None

def save_github_installation(installation: dict, make_active: bool = False):
    now = datetime.now(timezone.utc).isoformat()
    with connection() as db:
        has_active = db.execute('SELECT 1 FROM github_installations WHERE is_active = 1').fetchone()
        existing = db.execute('SELECT is_active FROM github_installations WHERE installation_id = ?', (installation['id'],)).fetchone()
        if make_active:
            db.execute('UPDATE github_installations SET is_active = 0')
            is_active = 1
        elif existing:
            is_active = existing[0]
        elif not has_active:
            is_active = 1
        else:
            is_active = 0

        db.execute(
            '''INSERT INTO github_installations
               (installation_id, account_login, account_type, account_avatar, repository_selection, installed_at, is_active)
               VALUES (?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(installation_id) DO UPDATE SET
               account_login=excluded.account_login,
               account_type=excluded.account_type,
               account_avatar=excluded.account_avatar,
               repository_selection=excluded.repository_selection,
               is_active=excluded.is_active''',
            (
                installation['id'],
                installation['account_login'],
                installation['account_type'],
                installation.get('avatar_url'),
                installation.get('repository_selection', 'all'),
                installation.get('installed_at', now),
                is_active
            )
        )

def get_github_installation(installation_id: int) -> Optional[dict]:
    with connection() as db:
        row = db.execute(
            '''SELECT installation_id, account_login, account_type, account_avatar, repository_selection, installed_at, is_active
               FROM github_installations WHERE installation_id = ?''',
            (installation_id,)
        ).fetchone()
    if row:
        return {
            'id': row[0],
            'account_id': row[0],
            'account_login': row[1],
            'account_type': row[2],
            'avatar_url': row[3],
            'repository_selection': row[4],
            'installed_at': row[5],
            'is_active': bool(row[6]),
        }
    return None

def disconnect_github_installation(installation_id: int):
    with connection() as db:
        was_active = db.execute('SELECT is_active FROM github_installations WHERE installation_id = ?', (installation_id,)).fetchone()
        db.execute('DELETE FROM github_installations WHERE installation_id = ?', (installation_id,))
        if was_active and was_active[0] == 1:
            remaining = db.execute('SELECT installation_id FROM github_installations ORDER BY installation_id DESC LIMIT 1').fetchone()
            if remaining:
                db.execute('UPDATE github_installations SET is_active = 1 WHERE installation_id = ?', (remaining[0],))

def get_active_github_installation() -> Optional[dict]:
    with connection() as db:
        row = db.execute(
            '''SELECT installation_id, account_login, account_type, account_avatar, repository_selection, installed_at
               FROM github_installations WHERE is_active = 1 ORDER BY installation_id DESC LIMIT 1'''
        ).fetchone()
    if row:
        return {
            'id': row[0],
            'account_id': row[0],
            'account_login': row[1],
            'account_type': row[2],
            'avatar_url': row[3],
            'repository_selection': row[4],
            'installed_at': row[5],
        }
    return None

def deactivate_github_installations():
    with connection() as db:
        db.execute('UPDATE github_installations SET is_active = 0')

def has_any_github_installation() -> bool:
    with connection() as db:
        row = db.execute('SELECT COUNT(*) FROM github_installations').fetchone()
        return bool(row and row[0] > 0)

def list_github_installations() -> list[dict]:
    with connection() as db:
        rows = db.execute(
            '''SELECT installation_id, account_login, account_type, account_avatar, repository_selection, installed_at, is_active
               FROM github_installations ORDER BY is_active DESC, installation_id DESC'''
        ).fetchall()
        return [
            {
                'id': r[0],
                'account_id': r[0],
                'account_login': r[1],
                'account_type': r[2],
                'avatar_url': r[3],
                'repository_selection': r[4],
                'installed_at': r[5],
                'is_active': bool(r[6]),
            }
            for r in rows
        ]

def set_active_github_installation(installation_id: int):
    with connection() as db:
        db.execute('UPDATE github_installations SET is_active = 0')
        db.execute('UPDATE github_installations SET is_active = 1 WHERE installation_id = ?', (installation_id,))


# ---------------------------------------------------------------------------
# Server-Managed Sessions & Scoped Installation Authorization (SQLite)
# ---------------------------------------------------------------------------

def create_session(ttl_days: int = 30, session_id: Optional[str] = None) -> str:
    """Creates or registers a server-managed session in SQLite with sliding TTL."""
    if not session_id:
        session_id = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    expires = now + timedelta(days=ttl_days)
    with connection() as db:
        db.execute(
            '''INSERT OR REPLACE INTO sessions (session_id, created_at, last_active, expires_at)
               VALUES (?, ?, ?, ?)''',
            (session_id, now.isoformat(), now.isoformat(), expires.isoformat())
        )
    return session_id

def get_session(session_id: Optional[str]) -> Optional[dict]:
    """Retrieves an active, unexpired session from SQLite."""
    if not session_id or not isinstance(session_id, str):
        return None
    now_iso = datetime.now(timezone.utc).isoformat()
    with connection() as db:
        row = db.execute(
            'SELECT session_id, created_at, last_active, expires_at FROM sessions WHERE session_id = ?',
            (session_id,)
        ).fetchone()
        if not row:
            return None
        sid, created_at, last_active, expires_at = row
        if expires_at < now_iso:
            db.execute('DELETE FROM sessions WHERE session_id = ?', (session_id,))
            return None
        return {
            'session_id': sid,
            'created_at': created_at,
            'last_active': last_active,
            'expires_at': expires_at,
        }

def touch_session(session_id: str, ttl_days: int = 30) -> bool:
    """Refreshes sliding expiration on each authenticated request."""
    if not session_id:
        return False
    now = datetime.now(timezone.utc)
    expires = now + timedelta(days=ttl_days)
    with connection() as db:
        res = db.execute(
            'UPDATE sessions SET last_active = ?, expires_at = ? WHERE session_id = ?',
            (now.isoformat(), expires.isoformat(), session_id)
        )
        return res.rowcount > 0

def revoke_session(session_id: str) -> None:
    """Explicitly revokes a session and clears its installation associations."""
    if not session_id:
        return
    with connection() as db:
        db.execute('DELETE FROM session_installations WHERE session_id = ?', (session_id,))
        db.execute('DELETE FROM sessions WHERE session_id = ?', (session_id,))

def authorize_installation_for_session(
    session_id: str,
    installation_id: int,
    make_selected: bool = False
) -> None:
    """Binds a GitHub installation to a specific session in SQLite.
    
    If make_selected is True or no installation is currently selected for the session,
    marks this installation as selected (is_selected=1) and unselects others.
    """
    now = datetime.now(timezone.utc)
    with connection() as db:
        # Ensure the session exists in the sessions table
        sess = db.execute('SELECT 1 FROM sessions WHERE session_id = ?', (session_id,)).fetchone()
        if not sess:
            expires = now + timedelta(days=30)
            db.execute(
                'INSERT INTO sessions (session_id, created_at, last_active, expires_at) VALUES (?, ?, ?, ?)',
                (session_id, now.isoformat(), now.isoformat(), expires.isoformat())
            )

        has_selected = db.execute(
            'SELECT 1 FROM session_installations WHERE session_id = ? AND is_selected = 1',
            (session_id,)
        ).fetchone()

        if make_selected or not has_selected:
            db.execute(
                'UPDATE session_installations SET is_selected = 0 WHERE session_id = ?',
                (session_id,)
            )
            is_selected = 1
        else:
            existing = db.execute(
                'SELECT is_selected FROM session_installations WHERE session_id = ? AND installation_id = ?',
                (session_id, installation_id)
            ).fetchone()
            is_selected = existing[0] if existing else 0

        db.execute(
            '''INSERT INTO session_installations (session_id, installation_id, is_selected)
               VALUES (?, ?, ?)
               ON CONFLICT(session_id, installation_id) DO UPDATE SET
               is_selected = excluded.is_selected''',
            (session_id, installation_id, is_selected)
        )

def get_session_installations(session_id: str) -> List[dict]:
    """Retrieves all installations explicitly authorized for this session."""
    with connection() as db:
        rows = db.execute(
            '''SELECT gi.installation_id, gi.account_login, gi.account_type, gi.account_avatar,
                      gi.repository_selection, gi.installed_at, gi.is_active, si.is_selected
               FROM session_installations si
               JOIN github_installations gi ON si.installation_id = gi.installation_id
               WHERE si.session_id = ?
               ORDER BY si.is_selected DESC, gi.installation_id DESC''',
            (session_id,)
        ).fetchall()
        return [
            {
                'id': r[0],
                'account_id': r[0],
                'account_login': r[1],
                'account_type': r[2],
                'avatar_url': r[3],
                'repository_selection': r[4],
                'installed_at': r[5],
                'is_active': bool(r[6]),
                'is_selected': bool(r[7]),
            }
            for r in rows
        ]

def get_session_selected_installation(session_id: str) -> Optional[dict]:
    """Retrieves the active/selected installation for this session."""
    with connection() as db:
        row = db.execute(
            '''SELECT gi.installation_id, gi.account_login, gi.account_type, gi.account_avatar,
                      gi.repository_selection, gi.installed_at, gi.is_active
               FROM session_installations si
               JOIN github_installations gi ON si.installation_id = gi.installation_id
               WHERE si.session_id = ? AND si.is_selected = 1
               LIMIT 1''',
            (session_id,)
        ).fetchone()
        if row:
            return {
                'id': row[0],
                'account_id': row[0],
                'account_login': row[1],
                'account_type': row[2],
                'avatar_url': row[3],
                'repository_selection': row[4],
                'installed_at': row[5],
                'is_active': bool(row[6]),
                'is_selected': True,
            }
    return None

def set_session_selected_installation(session_id: str, installation_id: int) -> bool:
    """Sets the selected installation for a given session."""
    with connection() as db:
        exists = db.execute(
            'SELECT 1 FROM session_installations WHERE session_id = ? AND installation_id = ?',
            (session_id, installation_id)
        ).fetchone()
        if not exists:
            return False
        db.execute('UPDATE session_installations SET is_selected = 0 WHERE session_id = ?', (session_id,))
        db.execute(
            'UPDATE session_installations SET is_selected = 1 WHERE session_id = ? AND installation_id = ?',
            (session_id, installation_id)
        )
        return True

def deauthorize_installation_for_session(session_id: str, installation_id: int) -> bool:
    """Removes an installation from this session and cleans up global active status if unreferenced."""
    with connection() as db:
        was_selected = db.execute(
            'SELECT is_selected FROM session_installations WHERE session_id = ? AND installation_id = ?',
            (session_id, installation_id)
        ).fetchone()
        if not was_selected:
            return False

        db.execute(
            'DELETE FROM session_installations WHERE session_id = ? AND installation_id = ?',
            (session_id, installation_id)
        )
        if was_selected[0] == 1:
            remaining = db.execute(
                'SELECT installation_id FROM session_installations WHERE session_id = ? ORDER BY installation_id DESC LIMIT 1',
                (session_id,)
            ).fetchone()
            if remaining:
                db.execute(
                    'UPDATE session_installations SET is_selected = 1 WHERE session_id = ? AND installation_id = ?',
                    (session_id, remaining[0])
                )

        # Check if any other session references this installation
        other = db.execute(
            'SELECT 1 FROM session_installations WHERE installation_id = ? LIMIT 1',
            (installation_id,)
        ).fetchone()
        if not other:
            db.execute('UPDATE github_installations SET is_active = 0 WHERE installation_id = ?', (installation_id,))
        return True

def is_installation_authorized_for_session(session_id: Optional[str], installation_id: int) -> bool:
    """Checks whether an installation is authorized for the given session."""
    if not session_id:
        return False
    with connection() as db:
        row = db.execute(
            'SELECT 1 FROM session_installations WHERE session_id = ? AND installation_id = ?',
            (session_id, installation_id)
        ).fetchone()
        return bool(row)

def get_session_authorized_installation_ids(session_id: Optional[str]) -> Set[int]:
    """Returns set of installation IDs authorized for the given session."""
    if not session_id:
        return set()
    with connection() as db:
        rows = db.execute(
            'SELECT installation_id FROM session_installations WHERE session_id = ?',
            (session_id,)
        ).fetchall()
        return {r[0] for r in rows}



