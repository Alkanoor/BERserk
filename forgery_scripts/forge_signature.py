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


#880 => 27
#1024 => 63
#1264 => 123
#research 116

"""
i = 256
while(i < 1650):
    a = Generator.forge_prefix(Generator.hexToInt(signature), 256, Generator.hexToInt(publicKeyModulo), i)
    print i
    i = i + 8
    if a != 0:
        print "success !!!"
        print a
        b = hex(a**3)
        print b
        if "1fffffffff" in b:
            print i - 8
            print "should be this"

print "fail"

"""

signature_high = Generator.forge_prefix(Generator.hexToInt(signature),256,Generator.hexToInt(publicKeyModulo),2048)
print "signature hight: %s\n" % Generator.intToHex(signature_high)

target_EM_high = signature_high ** 3
print "target_EM_high: %s\n" % Generator.intToHex(target_EM_high)

signature_low = Generator.forge_suffix(Generator.hexToInt(sha256),256,Generator.hexToInt(publicKeyModulo))
print "signature_low: %s\n" % Generator.intToHex(signature_low)

target_EM_Low = signature_low**3
print "target_EM_Low: %s\n" % Generator.intToHex(target_EM_Low)

print "sha256 + 1"
sha256 = Generator.hexToInt(sha256) + long(1)
print "message digest sha256: %s\n" % Generator.intToHex(sha256)

signature_low = Generator.forge_suffix(sha256,256,Generator.hexToInt(publicKeyModulo))
print "signature_low: %s\n" % Generator.intToHex(signature_low)

target_EM_Low = signature_low**3
print "target_EM_Low: %s\n" % Generator.intToHex(target_EM_Low)
