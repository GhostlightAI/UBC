"""Independent witness prototype. A checkpoint detects forks it has observed.

This is not global consensus: clients must compare independently held checkpoints.
Only hashes and pseudonymous device keys are retained here; no owner directory.
"""
import json,sqlite3,time
from .protocol import Identity,signed,canonical
from .device import verify_custody
import hashlib
class Witness:
    def __init__(self,path,identity):
        self.path=path;self.identity=identity
        with sqlite3.connect(path) as c:c.execute('CREATE TABLE IF NOT EXISTS heads(device_key TEXT PRIMARY KEY,sequence INTEGER,head TEXT)')
    def checkpoint(self,certificate,records,manufacturer_key):
        tip=verify_custody(certificate,records,manufacturer_key)
        if not records:raise ValueError('No ownership record')
        with sqlite3.connect(self.path,timeout=10) as c:
            c.execute('BEGIN IMMEDIATE');old=c.execute('SELECT sequence,head FROM heads WHERE device_key=?',(tip['device_key'],)).fetchone()
            if old:
                if old[0]>tip['sequence']:raise ValueError('Ownership history rollback detected')
                historical=hashlib.sha256(canonical(records[old[0]-1])).hexdigest()
                if old[1]!=historical:raise ValueError('Conflicting ownership history detected')
            c.execute('INSERT INTO heads VALUES(?,?,?) ON CONFLICT(device_key) DO UPDATE SET sequence=excluded.sequence,head=excluded.head',(tip['device_key'],tip['sequence'],tip['head']))
        return signed(self.identity,{'type':'custody-checkpoint','device_key':tip['device_key'],'sequence':tip['sequence'],'head':tip['head'],'at':int(time.time())})
