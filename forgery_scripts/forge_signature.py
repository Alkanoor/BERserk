#! /usr/bin/env python
'''The aim of this file is to create a script that can be call with 2 arguments :
- The message to signed
- The signature to copy

Can be used with :
./forge_signature.py inputs/message_a_signer.txt certifs/CA/signature certifs/CA/Alka.crt
'''


from optparse import OptionParser
from generator import Generator
import struct
import sys
import subprocess

parser = OptionParser()
parser.usage = """%prog messageFile signatureFile\nFor exemple: \n./forge_signature.py ../inputs/message_a_signer.txt ../certifs/CA/signature"""
parser.description = "Create a signature for a specified file"

(options, args) = parser.parse_args()

if len(args) != 3:
    parser.print_help(file=sys.stderr)
    sys.exit(1)

fd = open(args[0])
message = fd.read()
fd.close()

print "message: %s\n" % message

fd = open(args[1])
signature = Generator.strToHex(fd.read())
fd.close()


output = subprocess.Popen(["openssl", "asn1parse", "-in", args[1], "-inform", "DER"], stdout=subprocess.PIPE).communicate()[0]
signature = output.split("[HEX DUMP]:")[1]

print "signature: %s\n" % signature

sha256 = Generator.digest(message)

print "message digest sha256: %s\n" % sha256

output = subprocess.Popen(["openssl", "asn1parse", "-in", args[2], "-inform", "PEM"], stdout=subprocess.PIPE).communicate()[0]
value = output.split("rsaEncryption")[1].split("sha256WithRSAEncryption")[0].split("NULL")[1].split(":d=")[0]
offset = value.replace(" ","").replace("\n","")


output = subprocess.Popen(["openssl", "asn1parse", "-in", args[2], "-inform", "PEM", "-strparse", offset], stdout=subprocess.PIPE).communicate()[0]
publicKeyModulo = output.split("INTEGER")[1].split("\n")[0].split(":")[1]
print "puplicKeyModulo: %s\n" % publicKeyModulo


print Generator.hexToInt(sha256)
print Generator.hexToInt(publicKeyModulo)


for i in range(256, 1024):
    a = Generator.forge_prefix(Generator.hexToInt(sha256), 256, Generator.hexToInt(publicKeyModulo), i)
    if a != 0:
        print i
        print a
        break
print "fail"

Generator.forge_prefix(Generator.hexToInt(sha256),256,Generator.hexToInt(publicKeyModulo),512)

signature_low = Generator.forge_suffix(Generator.hexToInt(sha256),256,Generator.hexToInt(publicKeyModulo))
print Generator.intToHex(signature_low)

target_EM_Low = signature_low**3
print Generator.intToHex(target_EM_Low)