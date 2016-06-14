import binascii
import random
import math


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