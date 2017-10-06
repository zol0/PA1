import sys
from itertools import repeat
from multiprocessing import Pool, cpu_count
from cs483 import AESHelper
from cs483 import IO
from Crypto import Random

BSIZE = 16

def ctr_encrypt(a,iv,text):
    encrypted = a.encrypt(iv)
    cipher = a.xor(text,encrypted)
    return cipher

def increment_iv(iv):
    iv_int = (int.from_bytes(iv, sys.byteorder))+1
    return iv_int.to_bytes(len(iv), sys.byteorder)

if __name__ == "__main__":

    key = IO.getKey()
    msg = IO.getInput()
    iv = IO.getIV()

    if (iv == None): iv = Random.new().read(BSIZE)
    orig_iv = iv

    a = AESHelper(key)

    all_ivs = []
    msg_in_blocks = []
    msg_in_blocks.append(msg[:BSIZE])
    all_ivs.append(iv)

    i = BSIZE
    while (i < len(msg)):
        iv = increment_iv(iv)
        all_ivs.append(iv)
        msg_in_blocks.append(msg[i:i+BSIZE])
        i += BSIZE

    pool = Pool(cpu_count())
    finalCipher = pool.starmap(ctr_encrypt, zip(repeat(a), all_ivs, msg_in_blocks))
    finalCipher.insert(0, orig_iv)
    finalCipher = b''.join(finalCipher)

    with open(IO.args.output_file, "wb") as w:
        w.write(finalCipher)
