"""Small account repository: Supabase PostgreSQL, explicit shared-SQLite development mode."""
import json
import os
from contextlib import contextmanager
from datetime import datetime, timezone
from urllib.parse import urlparse, unquote

from fastapi import HTTPException
from . import storage

SQLITE_SCHEMA = '''
CREATE TABLE IF NOT EXISTS guardian_profiles (id TEXT PRIMARY KEY, email TEXT NOT NULL, display_name TEXT NOT NULL, avatar_url TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS guardian_devices (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES guardian_profiles(id), device_name TEXT NOT NULL, operating_system TEXT NOT NULL, cli_version TEXT NOT NULL, session_id TEXT NOT NULL, created_at TEXT NOT NULL, last_seen_at TEXT NOT NULL, revoked_at TEXT);
CREATE INDEX IF NOT EXISTS guardian_devices_owner ON guardian_devices(user_id);
CREATE TABLE IF NOT EXISTS guardian_revoked_sessions (user_id TEXT NOT NULL, session_id TEXT NOT NULL, revoked_at TEXT NOT NULL, PRIMARY KEY(user_id, session_id));
CREATE TABLE IF NOT EXISTS guardian_cloud_scans (id TEXT NOT NULL, user_id TEXT NOT NULL REFERENCES guardian_profiles(id), device_id TEXT NOT NULL REFERENCES guardian_devices(id), project_name TEXT NOT NULL, ecosystem TEXT NOT NULL, decision TEXT NOT NULL, severity_summary TEXT NOT NULL, report_payload TEXT NOT NULL, payload_sha256 TEXT NOT NULL, engine_version TEXT NOT NULL, scanned_at TEXT NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY(user_id,id));
CREATE INDEX IF NOT EXISTS guardian_scans_owner ON guardian_cloud_scans(user_id,created_at);
CREATE TABLE IF NOT EXISTS guardian_cli_authorizations (id TEXT PRIMARY KEY, state TEXT NOT NULL, challenge TEXT NOT NULL, redirect_uri TEXT NOT NULL, device_id TEXT NOT NULL, device_name TEXT NOT NULL, operating_system TEXT NOT NULL, cli_version TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, code_hash TEXT, consumed_at INTEGER);
'''


def now():
    return datetime.now(timezone.utc).isoformat()


def plain(row):
    return {key: value.isoformat() if isinstance(value, datetime) else value for key, value in dict(row).items()} if row else None


class AccountDB:
    def __init__(self, db, postgres):
        self.db, self.postgres = db, postgres

    def execute(self, sql, args=()):
        return self.db.execute(sql.replace('?', '%s') if self.postgres else sql, args)


class AccountStore:
    @contextmanager
    def connection(self):
        postgres = bool(os.getenv('GUARDIAN_DATABASE_URL'))
        if postgres:
            try:
                password=unquote(urlparse(os.environ['GUARDIAN_DATABASE_URL']).password or '').lower()
            except ValueError:
                password=''
            if password in {'[your-password]','your-password','your_password','<your-password>','[password]','<password>','password_here'}:
                raise HTTPException(503, 'GUARDIAN_DATABASE_URL still contains a placeholder password. Replace it in Guardian .env with your real Supabase PostgreSQL connection string and restart the API. For local SQLite, leave GUARDIAN_DATABASE_URL blank and keep GUARDIAN_ACCOUNT_STORE=sqlite.', headers={'X-Guardian-Error':'database_password_placeholder'})
            import psycopg
            from psycopg.rows import dict_row
            try:
                with psycopg.connect(os.environ['GUARDIAN_DATABASE_URL'], connect_timeout=5, prepare_threshold=None, row_factory=dict_row) as db:
                    yield AccountDB(db, True)
            except psycopg.Error as error:
                raise HTTPException(503, 'Account database unavailable. Check GUARDIAN_DATABASE_URL and apply the account migration.', headers={'X-Guardian-Error':'database_unavailable'}) from error
        elif os.getenv('GUARDIAN_ACCOUNT_STORE') == 'sqlite' and os.getenv('GUARDIAN_CLOUD_MODE', 'false').lower() != 'true':
            import sqlite3
            with storage.connection() as db:
                db.row_factory = sqlite3.Row
                db.executescript(SQLITE_SCHEMA)
                yield AccountDB(db, False)
        else:
            raise HTTPException(503, 'Set GUARDIAN_DATABASE_URL for Supabase PostgreSQL, or explicitly set GUARDIAN_ACCOUNT_STORE=sqlite for local development.', headers={'X-Guardian-Error':'database_not_configured'})

    def session_revoked(self, user_id, session_id):
        with self.connection() as db:
            return db.execute('SELECT 1 FROM guardian_revoked_sessions WHERE user_id=? AND session_id=?', (user_id, session_id)).fetchone() is not None

    def profile(self, user):
        with self.connection() as db:
            db.execute('INSERT INTO guardian_profiles(id,email,display_name,avatar_url,created_at) VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET email=excluded.email, display_name=excluded.display_name, avatar_url=excluded.avatar_url', (user.id,user.email,user.display_name,user.avatar_url,now()))
        return {'id':user.id,'email':user.email,'display_name':user.display_name,'avatar_url':user.avatar_url}

    def register(self, user, device, reauthorize=False):
        self.profile(user)
        timestamp = now()
        with self.connection() as db:
            old = db.execute('SELECT * FROM guardian_devices WHERE id=?', (device['id'],)).fetchone()
            if old and str(old['user_id']) != user.id:
                raise HTTPException(409, 'Device identifier is already registered to another account. Disconnect locally and use a new device identity.')
            if old and (old['revoked_at'] or str(old['session_id']) != user.session_id) and not reauthorize:
                raise HTTPException(403, 'Use guardian login to authorize this device again.')
            if old and str(old['session_id']) != user.session_id:
                db.execute('INSERT INTO guardian_revoked_sessions(user_id,session_id,revoked_at) VALUES(?,?,?) ON CONFLICT DO NOTHING',(user.id,str(old['session_id']),timestamp))
            db.execute('INSERT INTO guardian_devices(id,user_id,device_name,operating_system,cli_version,session_id,created_at,last_seen_at,revoked_at) VALUES(?,?,?,?,?,?,?,?,NULL) ON CONFLICT(id) DO UPDATE SET device_name=excluded.device_name, operating_system=excluded.operating_system, cli_version=excluded.cli_version, session_id=excluded.session_id, last_seen_at=excluded.last_seen_at, revoked_at=NULL', (device['id'],user.id,device['device_name'],device['operating_system'],device['cli_version'],user.session_id,timestamp,timestamp))
            row = db.execute('SELECT * FROM guardian_devices WHERE id=? AND user_id=?',(device['id'],user.id)).fetchone()
        result = plain(row)
        result.pop('session_id',None)
        return result

    def devices(self, user_id):
        with self.connection() as db:
            rows = db.execute('SELECT id,user_id,device_name,operating_system,cli_version,created_at,last_seen_at,revoked_at FROM guardian_devices WHERE user_id=? ORDER BY created_at DESC LIMIT 100',(user_id,)).fetchall()
        return [plain(row) for row in rows]

    def active_device(self, db, user, device_id):
        row = db.execute('SELECT * FROM guardian_devices WHERE id=? AND user_id=?' + (' FOR UPDATE' if db.postgres else ''), (device_id,user.id)).fetchone()
        if not row or row['revoked_at'] or str(row['session_id']) != user.session_id:
            raise HTTPException(403,'This device is absent, revoked, or bound to another login. Run guardian login.')
        return row

    def touch(self, user, device_id):
        with self.connection() as db:
            self.active_device(db,user,device_id)
            db.execute('UPDATE guardian_devices SET last_seen_at=? WHERE id=? AND user_id=?',(now(),device_id,user.id))
        return {'status':'connected'}

    def revoke(self, user, device_id):
        with self.connection() as db:
            row = db.execute('SELECT session_id FROM guardian_devices WHERE id=? AND user_id=?',(device_id,user.id)).fetchone()
            if not row:
                raise HTTPException(404,'Device not found.')
            timestamp = now()
            db.execute('UPDATE guardian_devices SET revoked_at=? WHERE id=? AND user_id=?',(timestamp,device_id,user.id))
            db.execute('INSERT INTO guardian_revoked_sessions(user_id,session_id,revoked_at) VALUES(?,?,?) ON CONFLICT DO NOTHING',(user.id,str(row['session_id']),timestamp))
        return {'status':'revoked','id':device_id}

    def upload(self, user, device_id, scan):
        self.profile(user)
        with self.connection() as db:
            self.active_device(db,user,device_id)
            db.execute('INSERT INTO guardian_cloud_scans(id,user_id,device_id,project_name,ecosystem,decision,severity_summary,report_payload,payload_sha256,engine_version,scanned_at,created_at) VALUES(?,?,?,?,?,?,' + ('CAST(? AS JSONB),CAST(? AS JSONB)' if db.postgres else '?,?') + ',?,?,?,?) ON CONFLICT(user_id,id) DO NOTHING', (scan['id'],user.id,device_id,scan['project_name'],scan['ecosystem'],scan['decision'],json.dumps(scan['severity_summary']),json.dumps(scan['report_payload']),scan['payload_sha256'],scan['engine_version'],scan['scanned_at'],now()))
            old = db.execute('SELECT payload_sha256 FROM guardian_cloud_scans WHERE id=? AND user_id=?',(scan['id'],user.id)).fetchone()
            if old['payload_sha256'] != scan['payload_sha256']:
                raise HTTPException(409,'This report ID already exists with different evidence. Local reports were preserved.')
            db.execute('UPDATE guardian_devices SET last_seen_at=? WHERE id=? AND user_id=?',(now(),device_id,user.id))
        return {'id':scan['id'],'status':'synchronized'}

    def scans(self, user_id):
        with self.connection() as db:
            rows = db.execute('SELECT s.id,s.device_id,s.project_name,s.ecosystem,s.decision,s.severity_summary,s.engine_version,s.scanned_at,s.created_at,d.device_name FROM guardian_cloud_scans s JOIN guardian_devices d ON d.id=s.device_id WHERE s.user_id=? ORDER BY s.created_at DESC LIMIT 100',(user_id,)).fetchall()
        result=[]
        for row in rows:
            value=plain(row)
            if isinstance(value['severity_summary'],str): value['severity_summary']=json.loads(value['severity_summary'])
            result.append(value)
        return result

    def overview(self, user_id):
        with self.connection() as db:
            rows=db.execute('SELECT decision,COUNT(*) AS count FROM guardian_cloud_scans WHERE user_id=? GROUP BY decision',(user_id,)).fetchall()
            devices=db.execute('SELECT COUNT(*) AS count FROM guardian_devices WHERE user_id=? AND revoked_at IS NULL',(user_id,)).fetchone()['count']
        distribution={key:0 for key in ('ALLOW','WARN','BLOCK','REVIEW')}
        distribution.update({row['decision']:row['count'] for row in rows})
        return {'total_scans':sum(distribution.values()),'decisions':distribution,'connected_devices':devices}

    def report(self, user_id, scan_id):
        with self.connection() as db:
            row=db.execute('SELECT report_payload FROM guardian_cloud_scans WHERE id=? AND user_id=?',(scan_id,user_id)).fetchone()
        if not row: raise HTTPException(404,'Report not found.')
        return json.loads(row['report_payload']) if isinstance(row['report_payload'],str) else row['report_payload']


account_store=AccountStore()
