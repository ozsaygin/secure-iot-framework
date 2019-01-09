import hash_chain as hc
from Crypto import Random
import base64
from Crypto.Cipher import AES
from Crypto.Util import Padding

class symmtrc_cypr:

    def __init__(self, p, q):
        self.HC = hc.hash_chain(11, p, q)
        self.key = self.HC.generate_key()[:16]
   
    def reKey(self):
        self.key = self.HC.generate_key()
        if self.key == None:
            print("Hash Chain finished. Auth required!")
            #
    def getKey(self):
        return self.key

    def encrypt(self, mess):
        raw = Padding.pad(mess.encode(), 128)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return Padding.unpad(cipher.decrypt(enc[AES.block_size:]), 128)