"""Experimental profile with transcript-bound keys and signed headers.

v0.1 address derivation is retained for discovery; the full Ed25519 key is
always the authority. v0.2 frames are intentionally not v0.1 wire compatible.
"""
import base64,json,os,time,uuid
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey,Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey,X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes,serialization
VERSION='ubc.experimental.0.2'
def b64(raw):return base64.b64encode(raw).decode('ascii')
def unb64(value):return base64.b64decode(value,validate=True)
def canonical(value):return json.dumps(value,ensure_ascii=True,sort_keys=True,separators=(',',':'),allow_nan=False).encode('ascii')
def raw_public(key):return key.public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
def address_from_public(public):
    if len(public)!=32:raise ValueError('Expected a 32-byte Ed25519 public key')
    n=int.from_bytes(public[:12]+b'\0'*4,'big');body='';alphabet='0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    for _ in range(15):n,r=divmod(n,36);body=alphabet[r]+body
    crc=0
    for byte in body.encode():
        crc^=byte
        for _ in range(8):crc=((crc<<1)^7)&255 if crc&128 else (crc<<1)&255
    return body+chr(65+crc%26)
class Identity:
    def __init__(self,key=None):self._key=key or Ed25519PrivateKey.generate()
    @property
    def public(self):return raw_public(self._key.public_key())
    @property
    def public_b64(self):return b64(self.public)
    @property
    def address(self):return address_from_public(self.public)
    def sign(self,body):return b64(self._key.sign(b'UBC-EXPERIMENTAL-0.2\0'+canonical(body)))
def signed(identity,body):return {'body':body,'public_key':identity.public_b64,'signature':identity.sign(body)}
def verify(packet,expected_key=None):
    if set(packet)!={'body','public_key','signature'}:raise ValueError('Unexpected signed packet fields')
    public=unb64(packet['public_key'])
    if expected_key and packet['public_key']!=expected_key:raise ValueError('The signer is not the pinned identity')
    Ed25519PublicKey.from_public_bytes(public).verify(unb64(packet['signature']),b'UBC-EXPERIMENTAL-0.2\0'+canonical(packet['body']))
    return packet['body']
class Session:
    """One-use ephemeral handshake; caller must verify a pinned peer's consent."""
    def __init__(self,identity,peer_key,tunnel_id=None):
        unb64(peer_key);self.identity=identity;self.peer_key=peer_key;self.id=tunnel_id or str(uuid.uuid4());self.ephemeral=X25519PrivateKey.generate();self.send_seq=0;self.received=set();self.created=int(time.time());self.expires=self.created+3600;self.send_key=self.receive_key=None
    def offer(self):
        return signed(self.identity,{'version':VERSION,'type':'handshake','tunnel_id':self.id,'from_key':self.identity.public_b64,'to_key':self.peer_key,'ephemeral_key':b64(raw_public(self.ephemeral.public_key())),'created':self.created,'expires':self.expires})
    def accept(self,packet):
        if self.send_key is not None:raise ValueError('This handshake was already completed')
        p=verify(packet,self.peer_key);now=int(time.time())
        if p['version']!=VERSION or p['type']!='handshake' or p['tunnel_id']!=self.id or p['to_key']!=self.identity.public_b64 or p['from_key']!=self.peer_key or not now-300<=p['created']<=now+30 or not now<p['expires']<=p['created']+3600:raise ValueError('Invalid or expired handshake')
        own=self.offer()['body'];transcript=canonical(sorted([own,p],key=lambda x:x['from_key']))
        shared=self.ephemeral.exchange(X25519PublicKey.from_public_bytes(unb64(p['ephemeral_key'])))
        keys=HKDF(algorithm=hashes.SHA256(),length=64,salt=None,info=b'UBC-v0.2-session\0'+transcript).derive(shared)
        first=self.identity.public_b64<self.peer_key
        self._send_material=keys[:32] if first else keys[32:];self._receive_material=keys[32:] if first else keys[:32];self.send_key=ChaCha20Poly1305(self._send_material);self.receive_key=ChaCha20Poly1305(self._receive_material);self.expires=min(self.expires,p['expires']);self.ephemeral=None
    def seal(self,body,kind='control'):
        if self.send_key is None or time.time()>=self.expires:raise ValueError('Session is not open')
        if kind not in ('text','control','file'):raise ValueError('Unsupported message type')
        plain=canonical(body)
        if len(plain)>32000:raise ValueError('Message too large')
        self.send_seq+=1
        header={'version':VERSION,'type':kind,'tunnel_id':self.id,'from_key':self.identity.public_b64,'to_key':self.peer_key,'seq':self.send_seq,'created':int(time.time()),'expires':self.expires}
        nonce=os.urandom(12);header['payload']=b64(nonce+self.send_key.encrypt(nonce,plain,canonical(header)))
        return signed(self.identity,header)
    def open(self,packet):
        p=verify(packet,self.peer_key);now=int(time.time())
        if self.receive_key is None or p['version']!=VERSION or p['tunnel_id']!=self.id or p['from_key']!=self.peer_key or p['to_key']!=self.identity.public_b64 or p['type'] not in ('text','control','file') or not now-300<=p['created']<=now+30 or not now<p['expires']<=self.expires or type(p['seq']) is not int or p['seq']<=0 or p['seq'] in self.received:raise ValueError('Wrong, expired or replayed frame')
        if len(self.received)>=1000:raise ValueError('Session message limit reached')
        header={k:v for k,v in p.items() if k!='payload'};raw=unb64(p['payload'])
        if len(raw)>33000:raise ValueError('Message too large')
        plain=self.receive_key.decrypt(raw[:12],raw[12:],canonical(header));value=json.loads(plain)
        self.received.add(p['seq']);return value
    def snapshot(self):
        """SECRET state. Persist only with company-bound authenticated encryption."""
        if self.send_key is None:raise ValueError('Only open sessions can be saved')
        return {'local_key':self.identity.public_b64,'peer_key':self.peer_key,'tunnel_id':self.id,'created':self.created,'expires':self.expires,'send_seq':self.send_seq,'received':sorted(self.received),'send_key':b64(self._send_material),'receive_key':b64(self._receive_material)}
    @classmethod
    def restore(cls,identity,state):
        if state['local_key']!=identity.public_b64 or state['expires']<=time.time():raise ValueError('Wrong or expired session snapshot')
        v=cls(identity,state['peer_key'],state['tunnel_id']);v.created=state['created'];v.expires=state['expires'];v.send_seq=state['send_seq'];v.received=set(state['received']);v.ephemeral=None
        v._send_material=unb64(state['send_key']);v._receive_material=unb64(state['receive_key']);v.send_key=ChaCha20Poly1305(v._send_material);v.receive_key=ChaCha20Poly1305(v._receive_material);return v
    def close(self):self.send_key=self.receive_key=self.ephemeral=self._send_material=self._receive_material=None;self.received.clear()
