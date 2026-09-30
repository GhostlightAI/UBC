import copy,hashlib,time
import pytest
from fastapi.testclient import TestClient
from ubc.protocol import Identity,Session,canonical,signed,verify,address_from_public
from ubc.device import Appliance,execution_request,verify_device
from ubc.relay import create_app
from ubc.client import RelayClient
from ubc.demo import run

def pair():
 a,b=Identity(),Identity();x=Session(a,b.public_b64);y=Session(b,a.public_b64,x.id);xo,yo=x.offer(),y.offer();x.accept(yo);y.accept(xo);return a,b,x,y

def test_encrypted_headers_replay_peer_and_tampering():
 a,b,x,y=pair();packet=x.seal({'private':'synthetic customer issue'});assert y.open(packet)=={'private':'synthetic customer issue'}
 with pytest.raises(ValueError):y.open(packet)
 for key,value in [('type','file'),('seq',55),('to_key',Identity().public_b64),('payload','AAAA')]:
  tampered=copy.deepcopy(packet);tampered['body'][key]=value
  with pytest.raises(Exception):y.open(tampered)
 with pytest.raises(Exception):verify(packet,Identity().public_b64)
 x.close()
 with pytest.raises(ValueError):x.seal({})

def owned():
 maker,owner,agent=Identity(),Identity(),Identity();box=Appliance(maker);verify_device(box.certificate,maker.public_b64);code=box.press_pairing_button();box.claim(signed(owner,box.claim_challenge(owner.public_b64)),code);return box,owner,agent

def test_ownership_and_scoped_grants():
 maker,owner,attacker=Identity(),Identity(),Identity();box=Appliance(maker);code=box.press_pairing_button()
 with pytest.raises(Exception):box.claim(signed(attacker,box.claim_challenge(owner.public_b64)),code)
 with pytest.raises(Exception):box.claim(signed(owner,box.claim_challenge(owner.public_b64)),'invented-code')
 box.claim(signed(owner,box.claim_challenge(owner.public_b64)),code)
 with pytest.raises(ValueError):box.press_pairing_button()
 grant=signed(owner,box.request(attacker.public_b64,'diagnose'));receipt=box.authorize(grant,execution_request(attacker,grant));assert verify(receipt,box.identity.public_b64)['result']['error']=='FILTER_RESTRICTED'
 with pytest.raises(ValueError):box.authorize(grant,execution_request(attacker,grant))
 repair=signed(owner,box.request(attacker.public_b64,'reset_filter_alert'))
 with pytest.raises(ValueError,match='filter'):box.authorize(repair,execution_request(attacker,repair))
 assert box.state['error']=='FILTER_RESTRICTED'
 with pytest.raises(ValueError):box.request(attacker.public_b64,'shell')

def test_revocation_transfer_and_wrong_device():
 box,owner,agent=owned();grant=signed(owner,box.request(agent.public_b64,'diagnose'))
 box.revoke(signed(owner,{'type':'device-revoke','device_id':box.device_id,'owner_epoch':box.owner_epoch,'grant_id':grant['body']['grant_id']}))
 with pytest.raises(ValueError):box.authorize(grant,execution_request(agent,grant))
 old=signed(owner,box.request(agent.public_b64,'diagnose'));box.release(signed(owner,{'type':'device-release','device_id':box.device_id,'owner_epoch':box.owner_epoch}));new=Identity();code=box.press_pairing_button();box.claim(signed(new,box.claim_challenge(new.public_b64)),code)
 with pytest.raises(Exception):box.authorize(old,execution_request(agent,old))
 other,_,_=owned()
 with pytest.raises(Exception):other.authorize(old,execution_request(agent,old))

def test_relay_blocks_unapproved_tunnel_and_cross_recipient_ack(tmp_path):
 a,b,x,y=pair()
 with TestClient(create_app(tmp_path/'relay.sqlite3')) as http:
  ac,bc=RelayClient(http,a),RelayClient(http,b);ac.request('announce');bc.request('announce')
  with pytest.raises(Exception):ac.request('signal',{'frame':x.seal({'secret':'hello'})})
  offer=Session(a,b.public_b64);answer=Session(b,a.public_b64,offer.id);o,r=offer.offer(),answer.offer();ac.request('connect',{'offer':o})
  outsider=RelayClient(http,Identity());outsider.request('announce');assert outsider.request('pending')['tunnels']==[]
  with pytest.raises(Exception):outsider.request('accept',{'tunnel_id':offer.id,'answer':r})
  bc.request('accept',{'tunnel_id':offer.id,'answer':r});offer.accept(r);answer.accept(o)
  frame=offer.seal({'secret':'customer data'});sent=ac.request('signal',{'frame':frame})
  with pytest.raises(Exception):ac.request('signal',{'frame':frame})
  outsider.request('ack',{'ids':[sent['id']]});pending=bc.request('pending');assert len(pending['frames'])==1 and answer.open(pending['frames'][0]['packet'])['secret']=='customer data'
  assert b'customer data' not in (tmp_path/'relay.sqlite3').read_bytes()
  bc.request('revoke',{'tunnel_id':offer.id})
  with pytest.raises(Exception):ac.request('signal',{'frame':offer.seal({})})

def test_demo():
 result=run();assert result['prototype'] and not result['real_hardware_access'] and len(result['steps'])==6

def test_custody_transfer_requires_both_owners_preserves_warranty_and_rejects_fork(tmp_path):
 from ubc.device import verify_custody
 from ubc.witness import Witness
 box,owner,agent=owned();new=Identity();warranty=box.warranty_until
 old_grant=signed(owner,box.request(agent.public_b64,'diagnose'))
 witness=Witness(tmp_path/'witness.sqlite3',Identity());witness.checkpoint(box.certificate,box.custody,box.manufacturer_key)
 first=box.transfer_request(new.public_b64)['body'];competing=box.transfer_request(Identity().public_b64)['body']
 with pytest.raises(Exception):box.transfer(signed(agent,first),signed(new,first))
 with pytest.raises(Exception):box.transfer(signed(owner,first),signed(agent,first))
 box.transfer(signed(owner,first),signed(new,first));assert box.owner_key==new.public_b64 and box.warranty_until==warranty
 assert verify_custody(box.certificate,box.custody,box.manufacturer_key)['owner_key']==new.public_b64
 with pytest.raises(Exception):box.authorize(old_grant,execution_request(agent,old_grant))
 with pytest.raises(Exception):box.transfer(signed(owner,competing),signed(new,competing))
 witness.checkpoint(box.certificate,box.custody,box.manufacturer_key)
 with pytest.raises(ValueError,match='rollback'):witness.checkpoint(box.certificate,box.custody[:1],box.manufacturer_key)
 forged=copy.deepcopy(box.custody);forged[1]['body']['to_owner']=agent.public_b64
 with pytest.raises(Exception):verify_custody(box.certificate,forged,box.manufacturer_key)
 # An expired warranty does not reassign ownership.
 box.warranty_until=0;assert box.owner_key==new.public_b64
