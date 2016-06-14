#! /usr/bin/env python

'''
Can be used with :
./forge_verify.py to_sign rsa_e_3
'''

from optparse import OptionParser
import sys
import subprocess
import hashlib
import utils
import binascii

parser = OptionParser()
parser.usage = """%prog messageFile rsaFile\n"""
parser.description = "Create a signature for a specified file"

(options, args) = parser.parse_args()

if len(args) != 2:
    parser.print_help(file=sys.stderr)
    sys.exit(1)

print "############### Getting the elements ###############"
#Get the message
fd = open(args[0])
message = fd.read()
fd.close()
print "message: %s\n" % message

#Hash the message with sha256
sha256 = hashlib.sha256(message).hexdigest()
print "message digest sha256: %s\n" % sha256
#check if odd or even

if not(long(sha256, 16) & long(1)):
    raise Exception('The hash must be odd')

#Get the publicKey
output = subprocess.Popen(["openssl", "asn1parse", "-in", args[1], "-inform", "PEM"], stdout=subprocess.PIPE).communicate()[0]
publicKey = output.split("INTEGER")[2].split(":")[1].split("\n")[0]
print "PublicKey: %s\n" % publicKey

#Get real signature
asn1 = "3031300d060960864801650304020105000420" + sha256
hex_data = asn1.decode("hex")
with open('base_hash_to_be_signed', 'wb') as f:
    f.write(bytearray(hex_data))
output = subprocess.Popen(["openssl", "rsautl", "-inkey", args[1], "-sign", "-in", "base_hash_to_be_signed", "-out", "signed"],stdout=subprocess.PIPE).communicate()[0]


with open('signed','r') as f:
    content = f.read()
print "Real signature: %s\n" % hex(long(binascii.hexlify(content),16))
result = (utils.verify(binascii.unhexlify(sha256),content,long(publicKey, 16)))
print "\nVerification success: %s\n" % result

print "############### Forging signature ###############"
#Forge signature
craft_sig = utils.craft_fake_sig(sha256, 'SHA-256', long(publicKey, 16))
print "\nCraft signature: %s\n" % hex(long(binascii.hexlify(craft_sig),16))

print "############### Verifying signature ###############"
#Verify signature
result = utils.verify(binascii.unhexlify(sha256), craft_sig, long(publicKey, 16))
print "\nVerification success: %s" % result
