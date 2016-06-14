#!/usr/bin/python


from utils import *
import binascii
import math


HASH_ASN1 = {
    'MD5': '\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05',
    'SHA-1': '\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05',
    'SHA-256': '\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05',
    'SHA-512': '\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05'
}

HASH_SIZE = {
    'MD5': 0x10,
    'SHA-1': 0x14,
    'SHA-256': 0x20,
    'SHA-512': 0x40
}


#verify allow us to check whether attack worked or not
#hash :      (byte string) to be equal to when signature is decrypted with pub key
#signature : (byte string) given from who signed the hash
#pub_key :   (big int) modulus in RSA
def verify(hash, signature, pub_key):
    n_bits = int(math.ceil(math.log(pub_key)/math.log(2.)))

    hash_int = int(binascii.hexlify(hash),16)
    signature_int = int(binascii.hexlify(signature),16)
    decrypted_int = pow(signature_int,3,pub_key)

    decrypted_hex = format(decrypted_int,'x')
    if len(decrypted_hex)%2 == 1:
        decrypted_hex = '0'+decrypted_hex
    decrypted_hex = '0'*(n_bits//4-len(decrypted_hex))+decrypted_hex
    decrypted = binascii.unhexlify(decrypted_hex)

    print("Signature deciphering : "+decrypted_hex)

    # signature  marker
    if decrypted[0:2] != b'\x00\x01':
        raise Exception('Bad signature or bad format')

    i = 3
    while decrypted[i] == b'\xff':
        i += 1

    if decrypted[i] != b'\x00':
        raise Exception('Bad signature or bad format')

    i += 1
    hash_type = 'None'
    for method in HASH_ASN1:
        if decrypted[i:i+len(HASH_ASN1[method])] == HASH_ASN1[method]:
            hash_type = method
            i += len(HASH_ASN1[method])
            break

    if hash_type == 'None':
        raise Exception('Hash type not supported or bad format')

    length,offset = BER_parse_length(decrypted[i:])

    i += offset
    if decrypted[i] != '\x04':
        raise Exception('Bad signature or bad format')

    i += 1
    length,offset = BER_parse_length(decrypted[i:])
    i += offset
    if hash != decrypted[i:i+length]:
         raise Exception('Verification failed')

    return True


with open('signed','r') as f:
    content = f.read()

N = int("00:d2:2a:7b:13:ee:c0:eb:e6:6e:09:10:4e:d3:30:bb:db:3a:73:d7:ab:2c:9d:19:8b:ac:0c:de:e5:08:ff:8c:4b:07:22:e7:98:b0:06:1e:16:64:a0:45:2d:8f:c4:af:34:85:a7:d5:c8:56:0c:76:16:74:31:18:21:08:3a:b2:a2:18:dd:2a:9f:bc:7b:af:ba:92:9b:7f:10:b5:76:5b:ac:88:4e:f2:da:e3:ef:27:df:f7:75:fe:4a:6a:ae:04:3e:94:b9:7a:43:4a:1d:f8:c1:d7:d4:3c:62:69:c2:af:fa:44:ed:1b:09:c9:5f:59:38:32:bc:b1:0d:07:d4:22:7c:e3:f0:36:9b:c1:21:85:fa:8f:a0:52:da:91:d4:04:df:5e:5f:61:b6:6e:9b:00:af:c8:b1:96:f4:2b:cf:b6:00:2e:5d:ff:aa:03:d7:10:68:ab:a3:64:5a:67:a1:6b:95:74:7d:ce:80:4c:eb:55:55:3d:23:68:6f:33:28:04:ba:60:07:09:b6:a0:c2:3b:5c:6c:2a:74:6f:44:b6:86:88:62:a4:4b:11:90:23:c5:a2:9b:75:f0:98:5e:8c:bf:ea:54:f0:13:be:a1:73:26:f5:c0:5f:8d:6e:8a:3a:97:19:51:ff:21:ca:d7:66:51:85:dd:29:a5:c3:80:90:88:9b".replace(':',''),16)
hash = "b0404b803c060d979488c4a145a5c4cb82c80102a0990967b2d55dc6601f7fd5"
print(verify(binascii.unhexlify(hash),content,N))


def craft_fake_sig(hex_message,hash_type,N):
    n_bits = int(math.ceil(math.log(N)/math.log(2.)))

    print(binascii.hexlify(HASH_ASN1[hash_type]))
    prefix = "0001FFFFFFFFFFFFFFFF00"+binascii.hexlify(HASH_ASN1[hash_type])
    hash_length = HASH_SIZE[hash_type]

    garbage_size_before_04FF = n_bits//8-len(prefix)//2-len(hex_message)//2-130

    prefix += format(garbage_size_before_04FF|0x80,'x')

    cbrt_prefix = find_cube_root_prefix(prefix,n_bits)
    #cbrt_middle = find_cube_root_prefix("04FF",n_bits-garbage_size_before_04FF*8-len(prefix)*4) doesn't work : we must bf
    cbrt_suffix = find_cube_root_suffix(hex_message,N)

    min_bits = int(math.ceil(math.log(cbrt_suffix)/math.log(2.)))

    good = cbrt_prefix+cbrt_suffix+int(random.random()*(1<<60))*(1<<min_bits)
    final = i_to_s(root(good))
    print(binascii.hexlify(final))
    while final[len(prefix)//2+garbage_size_before_04FF-1] != '\x04' or final[len(prefix)//2+garbage_size_before_04FF] != '\xff':
        good = cbrt_prefix+cbrt_suffix+int(random.random()*(1<<60))*(1<<min_bits)
        final = i_to_s(root(good))
    print(binascii.hexlify(final))

    ret = i_to_s(good)
    return "\x00"*(n_bits//8-len(ret))+ret

tmp = craft_fake_sig(hash,'SHA-256',N)
print(verify(binascii.unhexlify(hash),tmp,N))
