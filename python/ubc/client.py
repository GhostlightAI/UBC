"""Small reference relay client. Identity keys are supplied by the caller."""
from .protocol import VERSION,signed
class RelayClient:
    def __init__(self,http,identity):
        if http.base_url.scheme!='https' and http.base_url.host not in ('127.0.0.1','localhost','testserver'):raise ValueError('Remote relays require HTTPS')
        self.http=http;self.identity=identity
    def request(self,action,payload=None):
        r=self.http.post('/challenge',json={'public_key':self.identity.public_b64});r.raise_for_status();challenge=r.json()['challenge']
        packet=signed(self.identity,{'version':VERSION,'action':action,'challenge':challenge,'payload':payload or {}})
        r=self.http.post('/'+action,json=packet);r.raise_for_status();return r.json()
