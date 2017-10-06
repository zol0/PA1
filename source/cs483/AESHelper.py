import binascii, sys
from Crypto import Random
from Crypto.Cipher import AES

BSIZE = AES.block_size

class AESHelper:

    def __init__(self,key):
        self.key = key

    def encrypt(self,text):
        cipher = AES.new(self.key,1)
        return cipher.encrypt(text)

    def decrypt(self,text):
        cipher = AES.new(self.key,1)
        return cipher.decrypt(text)

    def xor(self, text, iv):
        iv = iv[:len(text)]
        iv_int = int.from_bytes(iv, sys.byteorder)
        plain_int = int.from_bytes(text, sys.byteorder)
        xor_int = plain_int ^ iv_int
        return xor_int.to_bytes(len(text), sys.byteorder)

    def unpad(self, msg):
        num_bytes = msg[-1]
        return msg[:len(msg)-num_bytes]

    def pad(self, msg):
        need = BSIZE - (len(msg) % BSIZE)
        msg += bytes([need])*need
        return msg

    def hello(self):
        print("hello")
