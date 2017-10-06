import sys
import binascii
import argparse

parser = argparse.ArgumentParser(description='Encrypt and/or decrypt some files')
parser.add_argument("-k", dest="key_file",help="File storing valid AES key as a hex encoded string")
parser.add_argument("-i", dest="input_file",help="File that is being operated on")
parser.add_argument("-o", dest="output_file",help="File where resulting output is stored")
parser.add_argument("-v", dest="optional_IV_file",help="File storing valid IV as hex encoded string")

args = parser.parse_args()

if (args.key_file == None):
    print("Must include a key file", file=sys.stderr)
    print("Rerun using '-h' for help", file=sys.stderr)
    sys.exit()
elif (args.input_file == None):
    print("Must include an input file", file=sys.stderr)
    print("Rerun using '-h' for help", file=sys.stderr)
    sys.exit()
elif (args.output_file == None):
    print("Must include an output file", file=sys.stderr)
    print("Rerun using '-h' for help", file=sys.stderr)
    sys.exit()

def getKey():
    with open(args.key_file, "rb") as k:
        key = k.read()
        key = binascii.unhexlify(key)
        return key
def getInput():
    with open(args.input_file, "rb") as f:
        s = f.read()
        return s

#def getOutput(w):
#    with open(args.output_file, "wb") as w:

def getIV():
    if (args.optional_IV_file != None):
        with open(args.optional_IV_file, "rb") as f:
            iv = f.read()
            iv = binascii.unhexlify(iv)
            return iv
    else: return None
