"""Run a local, synthetic appliance support conversation through the relay."""
import json,tempfile
from fastapi.testclient import TestClient
from .protocol import Identity,Session,signed,verify
from .relay import create_app
from .client import RelayClient
from .device import Appliance,execution_request,verify_device

def run():
    maker,owner,agent=Identity(),Identity(),Identity();box=Appliance(maker)
    cert=verify_device(box.certificate,maker.public_b64)
    physical_code=box.press_pairing_button();box.claim(signed(owner,box.claim_challenge(owner.public_b64)),physical_code)
    transcript=[{'step':'Manufacturer identity verified','device':cert['device_id']},{'step':'Owner proved key control and physical pairing'}]
    with tempfile.TemporaryDirectory(prefix='ubc-demo-') as folder,TestClient(create_app(folder+'/relay.sqlite3')) as http:
        a,b=RelayClient(http,agent),RelayClient(http,box.identity)
        a.request('announce');b.request('announce');outbound=Session(agent,box.identity.public_b64);inbound=Session(box.identity,agent.public_b64,outbound.id)
        offer,answer=outbound.offer(),inbound.offer();a.request('connect',{'offer':offer});b.request('accept',{'tunnel_id':outbound.id,'answer':answer});outbound.accept(answer);inbound.accept(offer)
        grant=signed(owner,box.request(agent.public_b64,'diagnose'));packet=outbound.seal({'grant':grant,'request':execution_request(agent,grant)})
        queued=a.request('signal',{'frame':packet});message=b.request('pending')['frames'][0];payload=inbound.open(message['packet']);result=verify(box.authorize(payload['grant'],payload['request']),box.identity.public_b64)
        b.request('ack',{'ids':[queued['id']]});transcript.append({'step':'Owner-authorized read-only diagnosis crossed the encrypted relay','result':result['result']})
        # The human performs this physical maintenance in the simulator.
        box.state['filter_clear']=True
        repair=signed(owner,box.request(agent.public_b64,'reset_filter_alert'));receipt=box.authorize(repair,execution_request(agent,repair));transcript.append({'step':'Separate owner approval reset the simulated alert','receipt':verify(receipt,box.identity.public_b64)['result']})
        try:box.authorize(repair,execution_request(agent,repair))
        except ValueError:transcript.append({'step':'Duplicate repair grant rejected'})
        a.request('revoke',{'tunnel_id':outbound.id});outbound.close();inbound.close();transcript.append({'step':'Tunnel revoked'})
    return {'prototype':True,'real_hardware_access':False,'creator':'Ryan Sloan','steps':transcript}
def main():print(json.dumps(run(),indent=2))
if __name__=='__main__':main()
