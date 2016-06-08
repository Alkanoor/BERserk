#! /usr/bin/env python
'''The aim of this file is to create a script that can be call with 2 arguments :
- The message to signed
- The signature to copy

Can be used with :
./forge_signature.py ../inputs/message_a_signer.txt ../certifs/CA/signature
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

if len(args) != 2:
    parser.print_help(file=sys.stderr)
    sys.exit(1)

fd = open(args[0])
message = fd.read()
fd.close()

fd = open(args[1])
signature = Generator.strToHex(fd.read())
fd.close()

print "message: %s\n" % message
print "signature : %s\n" % signature

sha256 = Generator.digest(message)

print "message digest sha256: %s\n" % sha256


output = subprocess.Popen(["openssl", "asn1parse", "-in", "certifs/CA/Alka.crt", "-inform", "PEM"], stdout=subprocess.PIPE).communicate()[0]
value = output.split("rsaEncryption")[1].split("sha256WithRSAEncryption")[0].split("NULL")[1].split(":d=")[0]
offset = value.replace(" ","").replace("\n","")

print "offset from open ssl: %s\n" % offset

output = subprocess.Popen(["openssl", "asn1parse", "-in", "certifs/CA/Alka.crt", "-inform", "PEM", "-strparse", offset], stdout=subprocess.PIPE).communicate()[0]
publicKeyModulo = output.split("INTEGER")[1].split("\n")[0].split(":")[1]
print publicKeyModulo
