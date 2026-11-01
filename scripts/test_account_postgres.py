"""Disposable local PostgreSQL integration check. Requires initdb/pg_ctl on PATH.
Creates a private temporary cluster; never connects to the configured Supabase database.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))


def main():
    initdb,pg_ctl=shutil.which('initdb'),shutil.which('pg_ctl')
    if not initdb or not pg_ctl: raise SystemExit('Install local PostgreSQL and put initdb/pg_ctl on PATH to run this optional integration check.')
    with tempfile.TemporaryDirectory(prefix='guardian-account-pg-',dir='/tmp') as folder:
        root=Path(folder);data=root/'data'
        subprocess.run([initdb,'-D',str(data),'-A','trust','--no-locale','-E','UTF8'],check=True,stdout=subprocess.DEVNULL)
        subprocess.run([pg_ctl,'-D',str(data),'-l',str(root/'postgres.log'),'-o',f"-k {folder} -c listen_addresses=''",'-w','start'],check=True,stdout=subprocess.DEVNULL)
        try:
            import psycopg
            from fastapi.testclient import TestClient
            from backend.guardian import account_auth
            from backend.guardian.account_store import account_store
            from backend.guardian.main import app
            from backend.tests.test_accounts import KEY,JWK,report,device
            import jwt
            url=f'postgresql:///postgres?host={folder}'
            os.environ.update(GUARDIAN_DATABASE_URL=url,SUPABASE_URL='https://guardian-test.supabase.co',SUPABASE_PUBLISHABLE_KEY='sb_publishable_test',GUARDIAN_CLOUD_MODE='true')
            a,b=str(uuid4()),str(uuid4());session=str(uuid4())
            with psycopg.connect(url,autocommit=True) as db:
                db.execute('CREATE ROLE anon; CREATE ROLE authenticated; CREATE SCHEMA auth; CREATE TABLE auth.users(id uuid PRIMARY KEY)')
                db.execute("CREATE FUNCTION auth.uid() RETURNS uuid LANGUAGE sql STABLE AS 'SELECT nullif(current_setting(''request.jwt.claim.sub'',true),'''')::uuid'")
                db.execute('GRANT USAGE ON SCHEMA auth TO authenticated; GRANT EXECUTE ON FUNCTION auth.uid() TO authenticated')
                db.execute(Path('supabase/migrations/202611010001_guardian_accounts.sql').read_text())
                db.execute('INSERT INTO auth.users VALUES(%s),(%s)',(a,b))
            def token(user):return jwt.encode({'sub':user,'session_id':session,'email':'test@example.test','role':'authenticated','aud':'authenticated','iss':'https://guardian-test.supabase.co/auth/v1','iat':int(time.time()),'exp':int(time.time())+3600},KEY,algorithm='RS256',headers={'kid':'test-key'})
            headers={'Authorization':'Bearer '+token(a)};other={'Authorization':'Bearer '+token(b)}
            with patch.object(account_auth.verifier,'keys',lambda issuer,kid:JWK):
                client=TestClient(app);d=device();r=report()
                assert client.post('/api/account/devices',headers=headers,json=d).status_code==200
                body={'report':r.model_dump(mode='json'),'consent':True,'device_id':d['id']}
                for _ in range(2):
                    result=client.post('/api/account/scans',headers=headers,json=body)
                    assert result.status_code==200,result.text
                scans=client.get('/api/account/scans',headers=headers).json()
                assert len(scans)==1 and scans[0]['severity_summary']['high']==1
                assert client.get('/api/account/scans/'+r.id,headers=other).status_code==404
                assert client.get('/api/account/overview',headers=headers).json()['total_scans']==1
                assert client.get('/api/account/scans/'+r.id,headers=headers).json()['cli']['decision']['decision']=='BLOCK'
                assert client.post('/api/account/devices/'+d['id']+'/revoke',headers=headers).status_code==200
                assert client.post('/api/account/scans',headers=headers,json=body).status_code==403
            with psycopg.connect(url) as db:
                db.execute('SET ROLE authenticated')
                db.execute("SELECT set_config('request.jwt.claim.sub',%s,true)",(a,))
                assert db.execute('SELECT count(*) FROM guardian_cloud_scans').fetchone()[0]==1
                db.execute("SELECT set_config('request.jwt.claim.sub',%s,true)",(b,))
                assert db.execute('SELECT count(*) FROM guardian_cloud_scans').fetchone()[0]==0
                assert db.execute("SELECT has_table_privilege('authenticated','guardian_cloud_scans','INSERT')").fetchone()[0] is False
                assert db.execute("SELECT has_table_privilege('authenticated','guardian_cli_authorizations','SELECT')").fetchone()[0] is False
            print('PostgreSQL migration, JSONB storage, duplicate upload, retrieval, ownership, revocation and RLS: passed.')
        finally:
            subprocess.run([pg_ctl,'-D',str(data),'-m','fast','-w','stop'],check=True,stdout=subprocess.DEVNULL)


if __name__=='__main__':main()
