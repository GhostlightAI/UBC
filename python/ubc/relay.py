"""Bounded SQLite mailbox relay for the experimental profile; never decrypts frames.

HTTP polling reference transport. WebRTC, federation and mobile background delivery
are deliberately outside this implementation. Put it behind HTTPS for remote use.
"""
import json,os,secrets,sqlite3,time
from contextlib import contextmanager
from pathlib import Path
from fastapi import FastAPI,HTTPException,Request
from pydantic import BaseModel,ConfigDict,Field
from .protocol import VERSION,verify,address_from_public,unb64,canonical
class Challenge(BaseModel):
    model_config=ConfigDict(extra='forbid')
    public_key:str=Field(min_length=44,max_length=44)
class Packet(BaseModel):
    model_config=ConfigDict(extra='forbid')
    body:dict;public_key:str=Field(min_length=44,max_length=44);signature:str=Field(min_length=88,max_length=88)
def create_app(path):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    @contextmanager
    def db():
        c=sqlite3.connect(path,timeout=10);c.row_factory=sqlite3.Row;c.execute('BEGIN IMMEDIATE')
        try:yield c;c.commit()
        except:c.rollback();raise
        finally:c.close()
    with db() as c:c.executescript('''CREATE TABLE IF NOT EXISTS challenges(nonce TEXT PRIMARY KEY,public_key TEXT,expires INTEGER);
    CREATE TABLE IF NOT EXISTS identities(address TEXT PRIMARY KEY,public_key TEXT UNIQUE,last_seen INTEGER);
    CREATE TABLE IF NOT EXISTS tunnels(id TEXT PRIMARY KEY,initiator TEXT,recipient TEXT,state TEXT,offer TEXT,answer TEXT,expires INTEGER);
    CREATE TABLE IF NOT EXISTS frames(id TEXT PRIMARY KEY,tunnel_id TEXT,sender TEXT,recipient TEXT,seq INTEGER,payload TEXT,expires INTEGER,UNIQUE(tunnel_id,sender,seq));
    CREATE TABLE IF NOT EXISTS frame_seen(tunnel_id TEXT,sender TEXT,seq INTEGER,expires INTEGER,PRIMARY KEY(tunnel_id,sender,seq));
    CREATE TABLE IF NOT EXISTS quotas(scope TEXT,minute INTEGER,count INTEGER,PRIMARY KEY(scope,minute));''')
    os.chmod(path,0o600);app=FastAPI(docs_url=None,redoc_url=None,openapi_url=None)
    @app.middleware('http')
    async def bound(request,call_next):
        if request.method=='POST':
            body=bytearray()
            async for chunk in request.stream():
                body.extend(chunk)
                if len(body)>64000:return __import__('starlette.responses',fromlist=['Response']).Response(status_code=413)
            request._body=bytes(body)
        response=await call_next(request);response.headers['Cache-Control']='no-store';return response
    def quota(c,scope,limit=60):
        minute=int(time.time())//60;c.execute('DELETE FROM quotas WHERE minute<?',(minute-2,))
        row=c.execute('SELECT count FROM quotas WHERE scope=? AND minute=?',(scope,minute)).fetchone()
        if row and row[0]>=limit:raise HTTPException(429,'Relay rate limit reached')
        c.execute('INSERT INTO quotas VALUES(?,?,1) ON CONFLICT(scope,minute) DO UPDATE SET count=quotas.count+1',(scope,minute))
    def cleanup(c):
        now=int(time.time());c.execute('DELETE FROM challenges WHERE expires<=?',(now,));c.execute('DELETE FROM frames WHERE expires<=?',(now,));c.execute('DELETE FROM tunnels WHERE expires<=?',(now,));c.execute('DELETE FROM frame_seen WHERE expires<=?',(now,))
    @app.get('/health')
    def health():return {'protocol':VERSION,'status':'experimental','transport':'http-poll','decrypts_messages':False}
    @app.post('/challenge')
    def challenge(m:Challenge,request:Request):
        try:address_from_public(unb64(m.public_key))
        except Exception:raise HTTPException(422,'Invalid public key')
        with db() as c:
            cleanup(c);quota(c,'ip:'+request.client.host,30)
            if c.execute('SELECT count(*) FROM challenges').fetchone()[0]>=10000:raise HTTPException(503,'Relay challenge capacity reached')
            nonce=secrets.token_urlsafe(24);expires=int(time.time())+60;c.execute('INSERT INTO challenges VALUES(?,?,?)',(nonce,m.public_key,expires));return {'challenge':nonce,'expires':expires}
    def authenticate(c,m,action):
        packet=m.model_dump()
        try:b=verify(packet)
        except Exception:raise HTTPException(401,'Signature verification failed')
        if set(b)!={'version','action','challenge','payload'} or b['version']!=VERSION or b['action']!=action:raise HTTPException(401,'Invalid relay request')
        r=c.execute('SELECT * FROM challenges WHERE nonce=?',(b['challenge'],)).fetchone()
        if not r or r['public_key']!=m.public_key or r['expires']<=time.time():raise HTTPException(401,'Expired or replayed challenge')
        c.execute('DELETE FROM challenges WHERE nonce=?',(b['challenge'],));quota(c,'key:'+m.public_key)
        if not isinstance(b['payload'],dict):raise HTTPException(422,'Relay payload must be an object')
        return b['payload']
    @app.post('/announce')
    def announce(m:Packet):
        with db() as c:
            authenticate(c,m,'announce');address=address_from_public(unb64(m.public_key));old=c.execute('SELECT * FROM identities WHERE address=?',(address,)).fetchone()
            if old and old['public_key']!=m.public_key:raise HTTPException(409,'Address collision: use a distinct identity and pin its full key')
            c.execute('INSERT INTO identities VALUES(?,?,?) ON CONFLICT(address) DO UPDATE SET last_seen=excluded.last_seen',(address,m.public_key,int(time.time())));return {'address':address,'public_key':m.public_key}
    @app.post('/connect')
    def connect(m:Packet):
        with db() as c:
            cleanup(c);p=authenticate(c,m,'connect')
            try:
                offer=p['offer'];b=verify(offer,m.public_key)
                if b['version']!=VERSION or b['type']!='handshake' or b['from_key']!=m.public_key or b['to_key']==m.public_key or not time.time()<b['expires']<=time.time()+3600:raise ValueError()
                from uuid import UUID
                UUID(b['tunnel_id'])
                if not c.execute('SELECT 1 FROM identities WHERE public_key=?',(b['to_key'],)).fetchone():raise ValueError()
            except Exception:raise HTTPException(422,'Invalid handshake offer or unknown pinned recipient')
            if c.execute('SELECT count(*) FROM tunnels WHERE initiator=?',(m.public_key,)).fetchone()[0]>=20:raise HTTPException(429,'Too many open tunnels')
            if c.execute('SELECT 1 FROM tunnels WHERE id=?',(b['tunnel_id'],)).fetchone():raise HTTPException(409,'Tunnel already exists')
            c.execute('INSERT INTO tunnels VALUES(?,?,?,?,?,?,?)',(b['tunnel_id'],m.public_key,b['to_key'],'pending',json.dumps(offer),None,b['expires']));return {'tunnel_id':b['tunnel_id'],'state':'pending'}
    @app.post('/accept')
    def accept(m:Packet):
        with db() as c:
            cleanup(c);p=authenticate(c,m,'accept');r=c.execute('SELECT * FROM tunnels WHERE id=?',(p.get('tunnel_id'),)).fetchone()
            if not r or r['recipient']!=m.public_key or r['state']!='pending':raise HTTPException(404,'Pending tunnel not found')
            try:
                b=verify(p['answer'],m.public_key)
                if b['version']!=VERSION or b['type']!='handshake' or b['tunnel_id']!=r['id'] or b['from_key']!=r['recipient'] or b['to_key']!=r['initiator'] or not time.time()<b['expires']<=time.time()+3600:raise ValueError()
            except Exception:raise HTTPException(422,'Invalid acceptance')
            c.execute("UPDATE tunnels SET state='open',answer=?,expires=? WHERE id=?",(json.dumps(p['answer']),min(b['expires'],r['expires']),r['id']));return {'state':'open'}
    @app.post('/pending')
    def pending(m:Packet):
        with db() as c:
            cleanup(c);authenticate(c,m,'pending')
            tunnels=[dict(r) for r in c.execute('SELECT * FROM tunnels WHERE initiator=? OR recipient=? LIMIT 40',(m.public_key,m.public_key))]
            for r in tunnels:r['offer']=json.loads(r['offer']);r['answer']=json.loads(r['answer']) if r['answer'] else None
            frames=[{'id':r['id'],'packet':json.loads(r['payload'])} for r in c.execute('SELECT * FROM frames WHERE recipient=? ORDER BY rowid LIMIT 50',(m.public_key,))]
            return {'tunnels':tunnels,'frames':frames}
    @app.post('/signal')
    def signal(m:Packet):
        with db() as c:
            cleanup(c);p=authenticate(c,m,'signal')
            try:f=verify(p['frame'],m.public_key)
            except Exception:raise HTTPException(401,'Invalid signed frame')
            r=c.execute('SELECT * FROM tunnels WHERE id=?',(f.get('tunnel_id'),)).fetchone()
            if not r or r['state']!='open' or m.public_key not in (r['initiator'],r['recipient']):raise HTTPException(404,'Open tunnel not found')
            if not isinstance(f.get('payload'),str) or len(f['payload'])>45000:raise HTTPException(422,'Invalid encrypted payload')
            target=r['recipient'] if r['initiator']==m.public_key else r['initiator']
            if f.get('version')!=VERSION or f.get('from_key')!=m.public_key or f.get('to_key')!=target or f.get('type') not in ('control','text','file') or type(f.get('seq')) is not int or not 0<f['seq']<2**53 or type(f.get('expires')) is not int or not time.time()<f['expires']<=r['expires']:raise HTTPException(422,'Frame is outside the negotiated tunnel')
            if c.execute('SELECT count(*) FROM frames WHERE tunnel_id=?',(r['id'],)).fetchone()[0]>=100:raise HTTPException(429,'Tunnel mailbox is full')
            import uuid
            ident=str(uuid.uuid4())
            if c.execute('SELECT count(*) FROM frame_seen WHERE tunnel_id=?',(r['id'],)).fetchone()[0]>=1000:raise HTTPException(429,'Session message limit reached')
            try:
                c.execute('INSERT INTO frame_seen VALUES(?,?,?,?)',(r['id'],m.public_key,f['seq'],f['expires']))
                c.execute('INSERT INTO frames VALUES(?,?,?,?,?,?,?)',(ident,r['id'],m.public_key,target,f['seq'],json.dumps(p['frame']),f['expires']))
            except sqlite3.IntegrityError:raise HTTPException(409,'Frame sequence was already queued')
            return {'id':ident,'queued':True}
    @app.post('/ack')
    def ack(m:Packet):
        with db() as c:
            p=authenticate(c,m,'ack');ids=p.get('ids',[])
            if not isinstance(ids,list) or len(ids)>50 or any(not isinstance(x,str) for x in ids):raise HTTPException(422,'Acknowledge up to fifty frame IDs')
            for ident in ids:c.execute('DELETE FROM frames WHERE id=? AND recipient=?',(ident,m.public_key))
            return {'acknowledged':True}
    @app.post('/revoke')
    def revoke(m:Packet):
        with db() as c:
            p=authenticate(c,m,'revoke');r=c.execute('SELECT * FROM tunnels WHERE id=?',(p.get('tunnel_id'),)).fetchone()
            if not r or m.public_key not in (r['initiator'],r['recipient']):raise HTTPException(404,'Tunnel not found')
            c.execute("UPDATE tunnels SET state='closed' WHERE id=?",(r['id'],));c.execute('DELETE FROM frames WHERE tunnel_id=?',(r['id'],));return {'state':'closed'}
    return app

def main():
    import argparse,uvicorn
    parser=argparse.ArgumentParser();parser.add_argument('--data',default='work/ubc-relay.sqlite3');parser.add_argument('--port',type=int,default=9450);args=parser.parse_args();uvicorn.run(create_app(args.data),host='127.0.0.1',port=args.port)
