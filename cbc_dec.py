from cs483 import AESHelper
from cs483 import IO

BSIZE = 16

def cbcdec(a,msg):
    iv = msg[:BSIZE]
    i = BSIZE
    decMsg = b''

    while (i < len(msg)):
        text = a.decrypt(msg[i:i+BSIZE])
        decMsg += a.xor(text,iv)
        iv = msg[i:i+BSIZE]
        i += BSIZE
    
    return decMsg

if __name__ == "__main__":

    key = IO.getKey()
    msg = IO.getInput()

    a = AESHelper(key)

    plain = cbcdec(a,msg)
    final_message = a.unpad(plain)

    with open(IO.args.output_file, "wb") as w:
        w.write(final_message)
