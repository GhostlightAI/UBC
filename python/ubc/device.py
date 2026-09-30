"""Simulated appliance with manufacturer identity, physical pairing and owner grants.

No shell, network, firmware update, or real hardware access is available.
"""
import hashlib,secrets,time,uuid
from .protocol import Identity,canonical,signed,verify,unb64
class Appliance:
    def __init__(self,manufacturer,device_id='SIM-WASHER-001',warranty_years=3):
        self.identity=Identity();self.manufacturer_key=manufacturer.public_b64;self.device_id=device_id
        self.certificate=signed(manufacturer,{'type':'device-certificate','device_id':device_id,'device_key':self.identity.public_b64,'model':'UBC simulated washer','expires':int(time.time())+86400*365})
        self.warranty_until=int(time.time())+warranty_years*365*86400;self.custody=[];self.transfers={};self.owner_key=None;self.owner_epoch=0;self.pairing=None;self.pair_failures=0;self.challenges={};self.used_grants=set();self.revoked_grants=set();self.audit=[];self.state={'error':'FILTER_RESTRICTED','filter_clear':False,'cycle_running':False,'pump_calibrated':False}
    def press_pairing_button(self):
        """Physical simulator control, deliberately absent from any remote API."""
        if self.owner_key:raise ValueError('Current owner must release the appliance before a new owner can pair')
        code=secrets.token_urlsafe(24);self.pairing=(hashlib.sha256(code.encode()).digest(),int(time.time())+120);self.pair_failures=0;return code
    def claim_challenge(self,owner_key):
        unb64(owner_key);nonce=secrets.token_urlsafe(24);body={'type':'ownership-claim','device_id':self.device_id,'device_key':self.identity.public_b64,'owner_key':owner_key,'nonce':nonce,'expires':int(time.time())+60};self.challenges[nonce]=body;return body
    def claim(self,packet,physical_code):
        body=verify(packet);expected=self.challenges.pop(body.get('nonce'),None)
        if not expected or expected!=body or body['expires']<=time.time() or packet['public_key']!=body['owner_key']:raise ValueError('Invalid ownership proof')
        if self.owner_key or not self.pairing or self.pairing[1]<=time.time() or self.pair_failures>=5:raise ValueError('Physical pairing unavailable')
        self.pair_failures+=1
        if not secrets.compare_digest(hashlib.sha256(physical_code.encode()).digest(),self.pairing[0]):raise ValueError('Physical pairing code does not match')
        self.owner_key=packet['public_key'];self.owner_epoch+=1;self.pairing=None;self.record_custody('claim',None,self.owner_key,packet,None);self.audit.append({'event':'owner_claimed','epoch':self.owner_epoch});return self.receipt('owner_claimed')
    def request(self,agent_key,action,args=None):
        if not self.owner_key:raise ValueError('Ownership is not established')
        if action not in ('diagnose','reset_filter_alert','calibrate_pump'):raise ValueError('Unknown appliance operation')
        args=args or {}
        if args:raise ValueError('This simulator accepts no operation arguments')
        return {'type':'device-grant','grant_id':str(uuid.uuid4()),'device_id':self.device_id,'device_key':self.identity.public_b64,'owner_epoch':self.owner_epoch,'agent_key':agent_key,'action':action,'arguments':args,'expires':int(time.time())+120,'max_uses':1}
    def authorize(self,grant,agent_request):
        g=verify(grant,self.owner_key);request=verify(agent_request,g['agent_key'])
        if g.get('type')!='device-grant' or g['device_id']!=self.device_id or g['device_key']!=self.identity.public_b64 or g['owner_epoch']!=self.owner_epoch or g['max_uses']!=1 or not time.time()<g['expires']<=time.time()+300 or g['grant_id'] in self.used_grants|self.revoked_grants:raise ValueError('Grant expired, revoked, consumed or for another device')
        if request!={'type':'device-execute','grant_hash':hashlib.sha256(canonical(grant)).hexdigest(),'device_id':self.device_id}:raise ValueError('Agent did not approve this exact request')
        if g['arguments'] or g['action'] not in ('diagnose','reset_filter_alert','calibrate_pump'):raise ValueError('Unsupported operation')
        self.used_grants.add(g['grant_id'])
        before=dict(self.state)
        try:
            if g['action']=='diagnose':result={'error':self.state['error'],'filter_clear':self.state['filter_clear'],'suggestion':'Inspect and clear the filter following the appliance manual. Repairs require a separate owner grant.'}
            else:
                if self.state['cycle_running']:raise ValueError('Safety interlock: stop the simulated cycle first')
                if g['action']=='reset_filter_alert':
                    if not self.state['filter_clear']:raise ValueError('Safety interlock: filter is still restricted')
                    self.state['error']=None
                else:self.state['pump_calibrated']=True
                result={'state':dict(self.state)}
        except Exception:
            self.state=before;self.audit.append({'event':'operation_blocked','action':g['action'],'grant_id':g['grant_id']});raise
        self.audit.append({'event':'operation_completed','action':g['action'],'grant_id':g['grant_id']});return self.receipt('operation_completed',result)
    def revoke(self,packet):
        b=verify(packet,self.owner_key)
        if b.get('type')!='device-revoke' or b.get('device_id')!=self.device_id or b.get('owner_epoch')!=self.owner_epoch:raise ValueError('Invalid revocation')
        self.revoked_grants.add(b['grant_id']);self.audit.append({'event':'grant_revoked','grant_id':b['grant_id']})
    def release(self,packet):
        b=verify(packet,self.owner_key)
        if b!={'type':'device-release','device_id':self.device_id,'owner_epoch':self.owner_epoch}:raise ValueError('Invalid release')
        old=self.owner_key;self.owner_key=None;self.owner_epoch+=1;self.challenges.clear();self.pairing=None;self.transfers.clear();self.record_custody('release',old,None,packet,None);self.audit.append({'event':'owner_released','epoch':self.owner_epoch})
    @property
    def custody_head(self):return hashlib.sha256(canonical(self.custody[-1])).hexdigest() if self.custody else hashlib.sha256(canonical(self.certificate)).hexdigest()
    def record_custody(self,event,old,new,approval,acceptance):
        body={'type':'custody-record','device_id':self.device_id,'device_key':self.identity.public_b64,'sequence':len(self.custody)+1,'previous':self.custody_head,'event':event,'from_owner':old,'to_owner':new,'owner_epoch':self.owner_epoch,'warranty_until':self.warranty_until,'approval':approval,'acceptance':acceptance}
        record=signed(self.identity,body);self.custody.append(record);return record
    def transfer_request(self,new_owner_key):
        if not self.owner_key or new_owner_key==self.owner_key:raise ValueError('A transfer needs distinct current and new owners')
        if len(unb64(new_owner_key))!=32:raise ValueError('Invalid new owner key')
        self.transfers={k:v for k,v in self.transfers.items() if v['expires']>time.time()}
        if len(self.transfers)>=10:raise ValueError('Too many pending transfer requests')
        body={'type':'ownership-transfer','request_id':str(uuid.uuid4()),'device_id':self.device_id,'device_key':self.identity.public_b64,'previous':self.custody_head,'sequence':len(self.custody)+1,'owner_epoch':self.owner_epoch,'from_owner':self.owner_key,'to_owner':new_owner_key,'expires':int(time.time())+600}
        self.transfers[body['request_id']]=body;return signed(self.identity,body)
    def transfer(self,owner_approval,new_owner_acceptance):
        body=verify(owner_approval,self.owner_key);expected=self.transfers.get(body.get('request_id'))
        if not expected or body!=expected or body['expires']<=time.time() or body['previous']!=self.custody_head or body['owner_epoch']!=self.owner_epoch:raise ValueError('Transfer is stale, expired or unrecognized')
        if verify(new_owner_acceptance,body['to_owner'])!=body:raise ValueError('Both owners must approve the exact same transfer')
        old=self.owner_key;self.owner_key=body['to_owner'];self.owner_epoch+=1;self.challenges.clear();self.transfers.clear();self.pairing=None
        result=self.record_custody('transfer',old,self.owner_key,owner_approval,new_owner_acceptance)
        self.audit.append({'event':'owner_transferred','epoch':self.owner_epoch});return result
    def receipt(self,event,result=None):return signed(self.identity,{'type':'device-receipt','device_id':self.device_id,'event':event,'at':int(time.time()),'result':result or {}})
def verify_device(certificate,manufacturer_key):
    c=verify(certificate,manufacturer_key)
    if c.get('type')!='device-certificate' or c['expires']<=time.time():raise ValueError('Manufacturer certificate expired')
    return c

def execution_request(agent,grant):return signed(agent,{'type':'device-execute','grant_hash':hashlib.sha256(canonical(grant)).hexdigest(),'device_id':grant['body']['device_id']})


def verify_custody(certificate,records,manufacturer_key):
    cert=verify_device(certificate,manufacturer_key);device_key=cert['device_key'];head=hashlib.sha256(canonical(certificate)).hexdigest();owner=None;epoch=0;warranty=None
    for sequence,record in enumerate(records,1):
        r=verify(record,device_key)
        if r['type']!='custody-record' or r['device_id']!=cert['device_id'] or r['device_key']!=device_key or r['sequence']!=sequence or r['previous']!=head or r['from_owner']!=owner or r['owner_epoch']!=epoch+1:raise ValueError('Custody chain is inconsistent')
        if warranty is not None and r['warranty_until']!=warranty:raise ValueError('An ownership transfer cannot rewrite the warranty')
        if r['event']=='claim':
            claim=verify(r['approval'],r['to_owner'])
            if owner is not None or claim.get('type')!='ownership-claim' or claim['device_id']!=cert['device_id'] or claim['device_key']!=device_key or claim['owner_key']!=r['to_owner']:raise ValueError('Invalid initial ownership claim')
        elif r['event']=='transfer':
            a=verify(r['approval'],owner);b=verify(r['acceptance'],r['to_owner'])
            if a!=b or a.get('type')!='ownership-transfer' or a['previous']!=head or a['sequence']!=sequence or a['owner_epoch']!=epoch or a['from_owner']!=owner or a['to_owner']!=r['to_owner'] or a['device_key']!=device_key or a['device_id']!=cert['device_id']:raise ValueError('Invalid transfer signatures')
        elif r['event']=='release':
            if verify(r['approval'],owner)!={'type':'device-release','device_id':cert['device_id'],'owner_epoch':epoch} or r['to_owner'] is not None:raise ValueError('Invalid release')
        else:raise ValueError('Unknown custody event')
        owner=r['to_owner'];epoch=r['owner_epoch'];warranty=r['warranty_until'];head=hashlib.sha256(canonical(record)).hexdigest()
    return {'device_key':device_key,'owner_key':owner,'owner_epoch':epoch,'sequence':len(records),'head':head,'warranty_until':warranty}
